"""Resolve the exact CodeQL toolchain in workspace-local copies; no study source is scanned."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from source_support import file_digest, local, write_json

CLI_ARCHIVE_SHA256 = "6ad2cead390cecf62dd59ae7ffd673d216902a9c00975ce107a362464a8b891e"
VERSIONS = {"codeql": "2.27.1", "codeql/python-all": "7.2.6", "codeql/python-queries": "1.8.11"}


def check_toolchain(root: Path, lock: dict) -> None:
    if lock["versions"] != VERSIONS:
        raise ValueError("Unexpected CodeQL/pack versions")
    for name, expected in lock["file_hashes"].items():
        if file_digest(local(root, name)) != expected:
            raise ValueError(f"Toolchain checksum mismatch: {name}")


def prepare(root: Path, codeql: Path, output: Path, record: Path) -> dict:
    if os.name != "posix":
        raise ValueError("Prepare and run the pinned Linux toolchain in Ubuntu/WSL")
    if record.exists():
        lock = json.loads(record.read_bytes())
        check_toolchain(root, lock)
        return lock
    if (
        file_digest(local(root, "artifacts/toolchains/codeql-linux64-2.27.1.zip"))
        != CLI_ARCHIVE_SHA256
    ):
        raise ValueError("Official CLI archive checksum mismatch")
    output.mkdir(parents=True, exist_ok=False)
    cache = local(root, "artifacts/toolchains/codeql-cache")
    cache.mkdir(parents=True, exist_ok=True)
    commands = []

    def run(name, arguments, *, cwd=None):
        command = [str(codeql), *arguments, f"--common-caches={cache}"]
        result = subprocess.run(
            command, cwd=cwd, capture_output=True, text=True, timeout=600, check=False
        )
        (output / f"{name}.stdout").write_text(result.stdout, encoding="utf-8")
        (output / f"{name}.stderr").write_text(result.stderr, encoding="utf-8")
        commands.append({"argv": command, "exit_code": result.returncode})
        if result.returncode:
            write_json(output / "failed_commands.json", commands)
            raise ValueError(f"CodeQL {name} failed; see {output / (name + '.stderr')}")
        return result.stdout

    version = json.loads(run("version", ["version", "--format=json"]))
    if version["version"] != VERSIONS["codeql"]:
        raise ValueError("Installed CodeQL CLI has a different version")
    packs = {}
    for key, source in (
        ("v02", "experiments/owasp-bp-pilot/ql_v02"),
        ("v03", "experiments/v03-interprocedural-guard/ql"),
        ("diagnostics", "experiments/wave-c/ql"),
    ):
        target = output / key
        shutil.copytree(
            local(root, source),
            target,
            ignore=shutil.ignore_patterns("__pycache__", ".cache", ".ruff_cache"),
        )
        packs[key] = target
    generated = subprocess.run(
        [sys.executable, "-I", str(packs["v02"] / "gen.py")],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    if generated.returncode:
        raise ValueError("Frozen first-party query generator failed")
    additional = "--additional-packs=" + os.pathsep.join(str(p) for p in packs.values())
    downloaded = json.loads(
        run(
            "download",
            [
                "pack",
                "download",
                "--format=json",
                "codeql/python-all@7.2.6",
                "codeql/python-queries@1.8.11",
            ],
        )
    )
    for key, directory in packs.items():
        run(f"install_{key}", ["pack", "install", str(directory), additional])
    resolved = json.loads(run("resolve", ["resolve", "qlpacks", "--format=json", additional]))
    # These commands only parse --help; no database is created or queried.
    for command in ("analyze", "run-queries"):
        run(f"help_{command}", ["database", command, "--rerun", "--help"])
    run("languages", ["resolve", "languages", "--format=json"])
    write_json(output / "commands.json", commands)
    names = {"artifacts/toolchains/codeql-linux64-2.27.1.zip", codeql.relative_to(root).as_posix()}
    for directory in (output, cache / "packages"):
        if directory.exists():
            for path in directory.rglob("*"):
                if path.is_file() and not any(
                    p.startswith(".") for p in path.relative_to(directory).parts
                ):
                    names.add(path.relative_to(root).as_posix())
    lock = {
        "version": "wave-c-toolchain-v1",
        "versions": VERSIONS,
        "cli": codeql.relative_to(root).as_posix(),
        "cli_version_output": version,
        "cache": cache.relative_to(root).as_posix(),
        "packs": {k: p.relative_to(root).as_posix() for k, p in packs.items()},
        "downloaded": downloaded,
        "resolved": resolved,
        "file_hashes": {name: file_digest(local(root, name)) for name in sorted(names)},
        "status": "versions_and_pack_resolution_verified_no_study_scan",
    }
    write_json(record, lock)
    return lock


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--codeql", default="artifacts/toolchains/codeql-2.27.1/codeql/codeql")
    parser.add_argument("--output", default="artifacts/wave-c/toolchain")
    parser.add_argument("--record", default="experiments/wave-c/toolchain.lock.json")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        root = args.root.resolve()
        if args.check:
            lock = json.loads(local(root, args.record).read_bytes())
            check_toolchain(root, lock)
        else:
            lock = prepare(
                root, local(root, args.codeql), local(root, args.output), local(root, args.record)
            )
        print(
            f"Verified CodeQL {lock['versions']['codeql']}, "
            f"{len(lock['file_hashes'])} toolchain inputs; no study scan"
        )
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"Toolchain preparation failed: {error}\n")


if __name__ == "__main__":
    main()
