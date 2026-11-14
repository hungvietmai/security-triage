"""Collect and score one split of pairs-v1 under Amendment 06.

    python experiments/evaluation/pairs-v1/score_pairs.py collect <run-dir>
    python experiments/evaluation/pairs-v1/score_pairs.py score <run-dir> [--json OUT]

`<run-dir>/labels.json` comes from pair_labels.py. `collect` scans every source once through
the running stack (../collect_report.py) into `<run-dir>/inputs/<pair id>/`; a pair that
already has a folder is skipped. `score` keeps only pairs whose scanned archive has the
SHA-256 of the source lock, scores them with ../independent-secbench/configurations.py and
lists every other pair with the reason it is left out.
"""

import argparse
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "independent-secbench"))
sys.path.insert(0, str(HERE))
import configurations  # noqa: E402
import pair_labels  # noqa: E402

PROFILE = "command-injection-v0.2"


def collect(run):
    labels = json.loads((run / "labels.json").read_bytes())
    log = run / "collection.log"
    for source in labels["sources"]:
        folder = run / "inputs" / source["id"]
        if folder.exists():
            continue
        if source["kind"] == "npm":
            coordinate = ["npm", source["package"], source["version"]]
        else:
            coordinate = ["github", source["owner"], source["repo"], source["commit"]]
        command = [sys.executable, str(HERE.parent / "collect_report.py"), str(folder), PROFILE]
        done = subprocess.run(
            command + coordinate, capture_output=True, text=True, encoding="utf-8", check=False
        )
        line = (
            f"{datetime.now(UTC).isoformat(timespec='seconds')} {source['id']} "
            f"exit={done.returncode} {(done.stdout + done.stderr).strip()}"
        )
        with log.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(line + "\n")
        print(line, flush=True)
    return 0


def score(labels, inputs):
    """Score the pairs scanned from the locked bytes; list the others with the reason."""
    checked = {row["id"]: row["locked_bytes"] for row in pair_labels.verify(labels, inputs)}
    reasons = {None: "no exported report", False: "scanned archive differs from the locked bytes"}
    left_out = [
        {"id": pair_id, "reason": reasons[state]}
        for pair_id, state in checked.items()
        if state is not True
    ]
    kept = {**labels, "sources": [s for s in labels["sources"] if checked[s["id"]] is True]}
    result = configurations.evaluate(kept, inputs)
    return {
        "split": labels["description"],
        "pairs": len(labels["sources"]),
        "scored_pairs": len(kept["sources"]),
        "left_out": left_out,
        "not_acquired_when_locked": labels.get("not_acquired", []),
        "result": result,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("action", choices=("collect", "score"))
    parser.add_argument("run", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv)
    if args.action == "collect":
        return collect(args.run)
    labels = json.loads((args.run / "labels.json").read_bytes())
    scored = score(labels, args.run / "inputs")
    if args.json:
        args.json.write_bytes((json.dumps(scored, indent=2, ensure_ascii=False) + "\n").encode())
    print(
        f"Pairs {scored['pairs']}, scored {scored['scored_pairs']}, left out {scored['left_out']}"
    )
    print(configurations.markdown(scored["result"]), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
