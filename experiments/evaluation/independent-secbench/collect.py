"""Scan every source of labels.json once through the running stack and save its exports.

Calls ../collect_report.py (unchanged) per source, in label order, and appends what it printed
to collection.log. A source that already has a folder is skipped: nothing is scanned twice.
A source whose scan cannot be exported gets no folder and is scored as missing.

    python experiments/evaluation/independent-secbench/collect.py
"""

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROFILE = "command-injection-v0.2"


def main():
    labels = json.loads((HERE / "labels.json").read_bytes())
    log = HERE / "collection.log"
    for source in labels["sources"]:
        folder = HERE / "inputs" / source["id"]
        if folder.exists():
            continue
        command = [
            sys.executable,
            str(HERE.parent / "collect_report.py"),
            str(folder),
            PROFILE,
            "npm",
            source["package"],
            source["version"],
        ]
        done = subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8", check=False
        )
        line = (
            f"{datetime.now(UTC).isoformat(timespec='seconds')} {source['id']} "
            f"exit={done.returncode} {(done.stdout + done.stderr).strip()}"
        )
        with log.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(line + "\n")
        print(line, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
