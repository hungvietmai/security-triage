"""Run the real CLI on authored synthetic input only; this is never a held-out study run."""

from __future__ import annotations

import argparse
import io
import json
import os
import tarfile
import time
from pathlib import Path

from evaluate import snapshot
from prepare_toolchain import check_toolchain
from run import run_snapshot
from source_support import file_digest, inspect_archive, local, write_json

APP = b"""from flask import Flask, request
app = Flask(__name__)

@app.route("/synthetic-file")
def synthetic_file():
    path = request.args.get("path")
    with open(path) as stream:
        return stream.read()
"""
MARKER = b'raise RuntimeError("synthetic source must not execute during extraction")\n'


def smoke(root: Path, directory: Path) -> dict:
    if os.name != "posix":
        raise ValueError("Run the Linux CLI smoke workflow in Ubuntu/WSL")
    toolchain = json.loads(local(root, "experiments/wave-c/toolchain.lock.json").read_bytes())
    check_toolchain(root, toolchain)
    directory.mkdir(parents=True, exist_ok=False)
    commit = "a" * 40
    archive_root = "wave-c-synthetic-" + commit
    archive = directory / "synthetic.tgz"
    with tarfile.open(archive, "w:gz") as bundle:
        for name, data in (("app.py", APP), ("tests/test_marker.py", MARKER)):
            member = tarfile.TarInfo(f"{archive_root}/{name}")
            member.size = len(data)
            bundle.addfile(member, io.BytesIO(data))
    source = {
        "rank": 1,
        "repository": "synthetic/wave-c-smoke",
        "commit": commit,
        "archive_root": archive_root,
        "archive_inventory": inspect_archive(archive, archive_root),
        "objects": {
            "archive": {
                "path": archive.relative_to(root).as_posix(),
                "size_bytes": archive.stat().st_size,
                "sha256": file_digest(archive),
            }
        },
    }
    result = run_snapshot(root, source, toolchain, directory / "snapshot", time.monotonic() + 3600)
    write_json(directory / "run.json", {"version": "synthetic-smoke-only", "records": [result]})
    if result["status"] != "completed":
        raise ValueError(f"Synthetic smoke did not complete: {result}")
    paths = {key: local(root, name) for key, name in result["files"].items()}
    report = snapshot(source["repository"], commit, paths)
    if report["counts"]["none"] < 1 or len(set(report["counts"].values())) != 1:
        raise ValueError("Synthetic dangerous source was missed or suppressed; smoke is not valid")
    if report["subset_violations"] or result["extraction"]["missing_python"]:
        raise ValueError("Synthetic smoke lost source coverage or violated subset chain")
    summary = {
        "synthetic_only": True,
        "status": "passed",
        "counts": report["counts"],
        "extraction": result["extraction"],
        "wall_seconds": result["wall_seconds"],
    }
    write_json(directory / "smoke_result.json", summary)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        root = args.root.resolve()
        print(json.dumps(smoke(root, local(root, args.output)), indent=2))
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"Synthetic smoke failed: {error}\n")


if __name__ == "__main__":
    main()
