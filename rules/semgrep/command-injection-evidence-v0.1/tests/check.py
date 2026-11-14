"""Check the dead-branch evidence rules against tests/cases.py with the pinned Semgrep.

Run where Semgrep is installed, for example inside the scan worker:

    docker compose exec -T worker python - < rules/semgrep/command-injection-evidence-v0.1/tests/check.py

The worker image carries the rules and cases under /srv/triage/rules/semgrep/. A function named
refuted_* must be reported by st-cmd-flow-none and not by st-cmd-flow-all; a function named
kept_* must be reported by both. Exits 1 on any mismatch.
"""

import ast
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

PACK = Path(os.environ.get("TRIAGE_ROOT", ".")) / "rules/semgrep/command-injection-evidence-v0.1"
cases = PACK / "tests" / "cases.py"
functions = [
    (node.name, node.lineno, node.end_lineno)
    for node in ast.parse(cases.read_text(encoding="utf-8")).body
    if isinstance(node, ast.FunctionDef) and not node.name.startswith("_")
]
with tempfile.TemporaryDirectory() as folder:
    (Path(folder) / "cases.py").write_bytes(cases.read_bytes())
    run = subprocess.run(
        ["semgrep", "scan", "--metrics=off", "--disable-version-check", "--disable-nosem",
         "--no-git-ignore", "--json", "--config", str(PACK / "dead-branch.yaml"), "."],
        cwd=folder, capture_output=True, text=True, encoding="utf-8", timeout=300, check=False,
    )
if run.returncode not in (0, 1):
    sys.exit(run.stderr[-2000:])
reported: dict[str, set[str]] = {}
for result in json.loads(run.stdout)["results"]:
    line = result["start"]["line"]
    owner = next((name for name, first, last in functions if first <= line <= last), None)
    reported.setdefault(result["check_id"].rsplit(".", 1)[-1], set()).add(owner)
failures = 0
for name, _, _ in functions:
    control = name in reported.get("st-cmd-flow-none", set())
    evidence = name in reported.get("st-cmd-flow-all", set())
    expected_refuted = name.startswith("refuted_")
    ok = control and (evidence != expected_refuted)
    failures += not ok
    print("ok  " if ok else "FAIL", name, f"control={control} evidence={evidence}")
print(f"{len(functions) - failures}/{len(functions)} cases as expected")
sys.exit(1 if failures else 0)
