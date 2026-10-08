"""Derive split-v0.2 from the frozen split-v0.1 under Amendment 05.

The only change: every reserve group (all JavaScript, held aside because their CWE is
unresolved) becomes development data. Held-out and excluded groups, the hash order and
every other field are carried over unchanged; nothing is redrawn or replaced.

    python experiments/make_split_v0_2.py [--check]
"""

import argparse
import copy
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "experiments/inventory/split_v0.1.json"
TARGET = ROOT / "experiments/inventory/split_v0.2.json"
AMENDMENT = "experiments/amendments/AMENDMENT_05_RESERVE_TO_DEVELOPMENT.md"
# Commit of tag split-v0.1, the frozen input of this derivation.
SOURCE_FREEZE_COMMIT = "67f77a381ba2be64b9686f046715223bb508c46c"


def derive(source):
    if source["split_id"] != "split-v0.1" or source["status"] != "pre_scan_frozen":
        raise ValueError("Require the frozen split-v0.1")
    split = copy.deepcopy(source)
    split.update(
        split_id="split-v0.2",
        date="2026-10-08",
        derived_from={
            "split_id": "split-v0.1",
            "tag": "split-v0.1",
            "freeze_commit": SOURCE_FREEZE_COMMIT,
        },
        amendment=AMENDMENT,
        scope_filter_only=False,
        reserve_reassigned_to_development=True,
    )
    for group in split["groups"]:
        if group["assignment"] == "reserve":
            if group["language"] != "javascript":
                raise ValueError(f"Amendment 05 covers JavaScript reserve only: {group['group_id']}")
            group["assignment"] = "development"
            group["previous_assignment"] = "reserve"  # its split-v0.1 assignment
            group["reason"] += "; reserve reassigned to development by Amendment 05"
    counts = {}
    for group in split["groups"]:
        counts.setdefault(group["language"], Counter())[group["assignment"]] += 1
    split["summary_by_language"] = {
        language: dict(sorted(counter.items())) for language, counter in sorted(counts.items())
    }
    return split


def render(split):
    return (json.dumps(split, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if split_v0.2.json is stale")
    args = parser.parse_args(argv)
    expected = render(derive(json.loads(SOURCE.read_text(encoding="utf-8"))))
    if args.check:
        current = TARGET.read_bytes() if TARGET.is_file() else b""
        if current != expected:
            print("stale:", TARGET.relative_to(ROOT).as_posix())
            return 1
        return 0
    TARGET.write_bytes(expected)
    print("wrote", TARGET.relative_to(ROOT).as_posix())
    return 0


if __name__ == "__main__":
    sys.exit(main())
