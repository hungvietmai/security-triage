"""Record and check the frozen configuration of the pairs-v1 held-out run (Amendment 08).

    python experiments/evaluation/pairs-v1/freeze.py write    # before the first development scan
    python experiments/evaluation/pairs-v1/freeze.py check    # exit 1 when a frozen file changed
    python experiments/evaluation/pairs-v1/freeze.py gate     # before the first held-out scan

`write` stores the SHA-256 of every frozen file in FROZEN_CONFIGURATION_v0.3.json. `gate`
repeats the check and, when nothing changed, writes HELD_OUT_GATE.json with the commit the
worktree is at. FROZEN_CONFIGURATION.json is the record of the v0.2 development run
(Amendment 06) and is no longer written or checked.
"""

import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
# What decides detection, merging, ranking, filtering and scoring. Adapters that only run a
# tool or acquire a source are left out on purpose: a crash there may be fixed between the
# development rehearsal and the held-out run.
PATTERNS = (
    "profiles/command-injection-v0.3/*",
    "profiles/command-injection-v0.2/priority-v0.2.yaml",
    "profiles/command-injection-v0.2/priority-v0.2.json",
    "profiles/command-injection-v0.2/rule-claims-v3.json",
    "backend/app/triage/*.py",
    # The target selection decides which files Semgrep sees.
    "backend/app/scanners/semgrep.py",
    "rules/semgrep/command-injection-evidence-v0.1/dead-branch.yaml",
    "rules/semgrep/command-injection-evidence-js-v0.1/constant-command.yaml",
    "rules/codeql/command-injection-evidence-v0.2/*.qll",
    "rules/codeql/command-injection-evidence-v0.2/*.yml",
    "rules/codeql/command-injection-evidence-v0.2/queries/*.ql",
    "experiments/locators/sink-locator-v1-javascript.yaml",
    "experiments/rules/python-upstream/*.yaml",
    "experiments/rules/batch-01/*.yaml",
    "tools/pins.env",
    "tools/bandit/bandit.ini",
    "tools/eslint/eslint.config.mjs",
    "tools/eslint/package-lock.json",
    "experiments/evaluation/collect_report.py",
    "experiments/evaluation/independent/known_sites.py",
    "experiments/evaluation/independent-secbench/configurations.py",
    "experiments/evaluation/pairs-v1/pair_labels.py",
    "experiments/evaluation/pairs-v1/score_pairs.py",
    "experiments/evaluation/pairs-v1/held_out/labels.json",
    "experiments/amendments/AMENDMENT_06_PRODUCT_PIPELINE_ON_PAIRS_V1.md",
    "experiments/amendments/AMENDMENT_08_HELD_OUT_WITH_V0_3.md",
)


def hashes(root=ROOT):
    found = {}
    for pattern in PATTERNS:
        matches = sorted(path for path in root.glob(pattern) if path.is_file())
        if not matches:
            raise SystemExit(f"no file matches {pattern}")
        for path in matches:
            found[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return found


def changed(record, current):
    names = sorted(set(record) | set(current))
    return [name for name in names if record.get(name) != current.get(name)]


def main(argv=None):
    action = (argv if argv is not None else sys.argv[1:])[0]
    target = HERE / "FROZEN_CONFIGURATION_v0.3.json"
    if action == "write":
        record = {
            "written_utc": datetime.now(UTC).isoformat(timespec="seconds"),
            "sha256": hashes(),
        }
        target.write_bytes((json.dumps(record, indent=2) + "\n").encode())
        print(f"{len(record['sha256'])} files frozen")
        return 0
    drift = changed(json.loads(target.read_bytes())["sha256"], hashes())
    if drift:
        print("frozen files changed:", drift)
        return 1
    print("frozen configuration unchanged")
    if action == "gate":
        commit = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        ).stdout.strip()
        gate = {
            "checked_utc": datetime.now(UTC).isoformat(timespec="seconds"),
            "commit": commit,
            "frozen_files_unchanged": True,
            "statement": "Written before the first held-out scan.",
        }
        (HERE / "HELD_OUT_GATE.json").write_bytes((json.dumps(gate, indent=2) + "\n").encode())
        print("gate recorded at", commit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
