"""Acquire wave C metadata and bounded archives; never execute source or a scanner."""

from __future__ import annotations

import argparse
import collections
import subprocess
import sys
from pathlib import Path

from source_support import local, prepare


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument(
        "--check", action="store_true", help="Verify only; never refetch TOFU bytes"
    )
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        # Check the frozen method, selection and its protected input metadata first.
        verifier = root / "experiments/v03-interprocedural-guard/scripts/verify_freeze.py"
        for manifest in (
            "experiments/wave-c/LOCK.sha256",
            "experiments/v03-interprocedural-guard/FREEZE_v0.3_dual.sha256",
        ):
            subprocess.run(
                [sys.executable, str(verifier), "--root", str(root), "--manifest", manifest],
                check=True,
            )
        subprocess.run(
            [
                sys.executable,
                str(root / "experiments/wave-c/select_repositories.py"),
                "--root",
                str(root),
                "--check",
            ],
            check=True,
        )
        lock = prepare(
            root,
            local(root, "experiments/wave-c/inventory.json"),
            local(root, "experiments/wave-c/exclusions.json"),
            local(root, "experiments/wave-c/sources.lock.json"),
            local(root, "artifacts/wave-c/sources"),
            check=args.check,
        )
        print("Acquisition:", dict(collections.Counter(row["status"] for row in lock["records"])))
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Source preparation failed: {error}\n")


if __name__ == "__main__":
    main()
