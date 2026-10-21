"""Post-hoc reporting only: query copies of the two alert-producing Wave C DBs.

Run with Linux Python under WSL, from the repository root. Never imports source.
An existing output directory is rejected. No network or dependency installation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time
from datetime import datetime, timezone


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def manifest(directory):
    files = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"Database symlink rejected: {path}")
        if path.is_file():
            files[path.relative_to(directory).as_posix()] = digest(path)
    return files


def save(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if os.name != "posix":
        parser.error("Run with Linux Python under WSL")
    root = Path.cwd().resolve()
    output = (root / args.output).resolve()
    if not output.is_relative_to(root / "artifacts/wave-c"):
        parser.error("Output must be a fresh directory under artifacts/wave-c")
    output.mkdir(parents=True, exist_ok=False)
    bundle = root / "experiments/wave-c/results/paths-001"
    pack = bundle / "pack"
    cli = root / "artifacts/toolchains/codeql-2.27.1/codeql/codeql"
    cache = root / "artifacts/toolchains/codeql-cache"
    record = {
        "classification": "post-hoc exploratory review aid; not primary evaluation",
        "started_at": now(),
        "primary_results_changed": False,
        "application_source_executed": False,
        "human_review_seconds": 0,
        "pack_inputs": manifest(pack),
        "commands": [],
        "databases": {},
    }

    def run(argv, name, timeout=1200):
        start = time.monotonic()
        entry = {"argv": list(map(str, argv)), "started_at": now(), "timeout_seconds": timeout}
        with (output / f"{name}.stdout.log").open("wb") as stdout:
            with (output / f"{name}.stderr.log").open("wb") as stderr:
                proc = subprocess.Popen(entry["argv"], stdout=stdout, stderr=stderr, start_new_session=True)
                try:
                    entry["exit_code"] = proc.wait(timeout=timeout)
                    entry["status"] = "ok" if entry["exit_code"] == 0 else "failed"
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    entry["exit_code"] = proc.wait()
                    entry["status"] = "timeout"
        entry["wall_seconds"] = time.monotonic() - start
        record["commands"].append(entry)
        save(output / "run.json", record)
        print(f"{name}: {entry['status']} ({entry['wall_seconds']:.1f}s)", flush=True)
        if entry["status"] != "ok":
            raise RuntimeError(f"Command did not complete: {name}")

    try:
        run([cli, "version", "--format=json"], "version", 60)
        version = json.loads((output / "version.stdout.log").read_bytes())
        if version["version"] != "2.27.1":
            raise ValueError("CodeQL version changed")
        for rank in ("03", "08"):
            original = root / "artifacts/wave-c/study-001" / rank / "database"
            copied = output / rank / "database"
            before = manifest(original)
            record["databases"][rank] = {"original": str(original), "original_before": before}
            print(f"Copying database {rank}: {len(before)} files", flush=True)
            shutil.copytree(original, copied)
            if manifest(copied) != before:
                raise ValueError("Database copy differs")
            record["databases"][rank]["copy_verified_before_queries"] = True
            options = ["--rerun", "--threads=2", "--ram=5000", f"--common-caches={cache}"]
            run([cli, "database", "analyze", copied, pack / "ReviewPaths.ql",
                 f"--additional-packs={pack}", "--format=sarif-latest",
                 f"--output={output / rank / 'paths.sarif'}", *options], f"{rank}-paths")
            run([cli, "database", "run-queries", copied, pack / "ReviewEdges.ql",
                 f"--additional-packs={pack}", *options], f"{rank}-edges")
            bqrs = list((copied / "results").rglob("ReviewEdges.bqrs"))
            if len(bqrs) != 1:
                raise ValueError(f"Expected one edge result, found {bqrs}")
            for fmt in ("csv", "json"):
                run([cli, "bqrs", "decode", bqrs[0], f"--format={fmt}",
                     f"--output={output / rank / ('edges.' + fmt)}"], f"{rank}-decode-{fmt}")
            after = manifest(original)
            record["databases"][rank]["original_after"] = after
            record["databases"][rank]["original_unchanged"] = after == before
            if after != before:
                raise ValueError("Original database changed")
        record["status"] = "completed"
    except Exception as error:
        record["status"] = "failed"
        record["error"] = repr(error)
        raise
    finally:
        record["finished_at"] = now()
        save(output / "run.json", record)


if __name__ == "__main__":
    main()
