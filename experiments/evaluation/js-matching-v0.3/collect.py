"""Rescan the JavaScript npm sources of earlier runs with profile command-injection-v0.3.

    python experiments/evaluation/js-matching-v0.3/collect.py sources   # write sources.json
    python experiments/evaluation/js-matching-v0.3/collect.py scan      # needs the running stack

`sources` lists every npm source that has a saved v0.2 export in ../independent-secbench,
../inputs or ../pairs-v1/development, with the folder of that export. `scan` scans each source
once with v0.3 (../collect_report.py) into inputs/<id>/; a source that has a folder is skipped.

All of these sources were scanned before, and some were read to find the defects v0.3 fixes
(`used_to_fix` in sources.json). This is development data, not an independent test.
"""

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
EVALUATION = HERE.parent
PROFILE = "command-injection-v0.3"
# Packages whose source was read while diagnosing the matching failures and the filter group.
USED_TO_FIX = {
    "adb-driver@0.1.8",
    "kill-process-by-name@1.0.5",
    "node-unrar@0.1.0",
    "umount@1.1.6",
    "ps-visitor@0.0.2",
    "enpeem@2.2.0",
    "arpping@2.0.0",
    "curling@0.2.0",
    "buns@1.1.6",
    "ts-process-promises@1.0.2",
}
GROUPS = (
    ("I2", EVALUATION / "independent-secbench" / "inputs", ""),
    ("dev-npm", EVALUATION / "inputs", "npm-"),
    ("pairs-dev", EVALUATION / "pairs-v1" / "development" / "inputs", "secbench-"),
)


def sources():
    found = {}
    for group, root, prefix in GROUPS:
        for folder in sorted(p for p in root.iterdir() if p.is_dir() and p.name.startswith(prefix)):
            report = json.loads((folder / "report.json").read_bytes())
            coordinate = report["snapshot"]["source_coordinate"]
            if not coordinate.startswith("npm:") or report["snapshot"]["status"] != "ready":
                continue
            package, _, version = coordinate[4:].rpartition("@")
            entry = found.setdefault(
                coordinate[4:],
                {
                    "id": coordinate[4:].replace("/", "__").replace("@", "_"),
                    "package": package,
                    "version": version,
                    "used_to_fix": coordinate[4:] in USED_TO_FIX,
                    "before": [],
                },
            )
            entry["before"].append(
                {
                    "group": group,
                    "export": folder.relative_to(EVALUATION).as_posix(),
                    "scan_status": report["status"],
                }
            )
    return {"profile": PROFILE, "sources": [found[key] for key in sorted(found)]}


def scan():
    listed = json.loads((HERE / "sources.json").read_bytes())
    log = HERE / "collection.log"
    for source in listed["sources"]:
        folder = HERE / "inputs" / source["id"]
        if folder.exists():
            continue
        command = [
            sys.executable,
            str(EVALUATION / "collect_report.py"),
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


def main(argv=None):
    action = (argv if argv is not None else sys.argv[1:])[0]
    if action == "sources":
        listed = sources()
        (HERE / "sources.json").write_bytes(
            (json.dumps(listed, indent=2, ensure_ascii=False) + "\n").encode()
        )
        fix = sum(1 for source in listed["sources"] if source["used_to_fix"])
        print(f"{len(listed['sources'])} sources, {fix} of them read to design the fix")
        return 0
    return scan()


if __name__ == "__main__":
    raise SystemExit(main())
