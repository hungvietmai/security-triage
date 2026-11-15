"""Check constant-command.yaml against tests/cases.js with the pinned Semgrep.

Run inside the worker image from the repository copy at /srv/triage:

    docker compose exec -T worker python - \
        < rules/semgrep/command-injection-evidence-js-v0.1/tests/check.py

A function named constant_* must have its exec call reported; kept_* must not. The script
copies the cases to a temporary folder, so the scanned file is never executed.
"""

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PACK = Path("/srv/triage/rules/semgrep/command-injection-evidence-js-v0.1")


def main():
    folder = Path(tempfile.mkdtemp())
    shutil.copy(PACK / "tests" / "cases.js", folder / "cases.js")
    done = subprocess.run(
        ["semgrep", "scan", "--config", str(PACK / "constant-command.yaml"), "--json", "--quiet",
         "--metrics=off", "--disable-version-check", "cases.js"],
        cwd=folder, capture_output=True, text=True, encoding="utf-8", check=False,
    )
    reported = {result["start"]["line"] for result in json.loads(done.stdout)["results"]}
    wrong = []
    names = []
    lines = (folder / "cases.js").read_text(encoding="utf-8").splitlines()
    for number, line in enumerate(lines, 1):
        match = re.match(r"function (constant_\w+|kept_\w+)\(", line)
        if not match:
            continue
        name = match.group(1)
        names.append(name)
        if name.startswith("constant_") != (number in reported):
            wrong.append(name)
    constant = sum(1 for name in names if name.startswith("constant_"))
    print(f"{len(names) - len(wrong)}/{len(names)} cases as expected "
          f"({constant} constant, {len(names) - constant} kept); wrong: {wrong}")
    return 1 if wrong else 0


if __name__ == "__main__":
    sys.exit(main())
