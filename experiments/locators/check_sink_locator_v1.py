"""Check sink-locator-v1-javascript.yaml against its synthetic cases with the pinned Semgrep.

Run inside the worker image from the repository copy at /srv/triage:

    docker compose exec -T worker python - < experiments/locators/check_sink_locator_v1.py

Lines of fixtures/sink-locator-v1-cases.js ending in "// locate" must be reported, lines ending
in "// skip" must not. The cases are copied to a temporary folder and only parsed.
"""

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

LOCATORS = Path("/srv/triage/experiments/locators")


def main():
    folder = Path(tempfile.mkdtemp())
    shutil.copy(LOCATORS / "fixtures" / "sink-locator-v1-cases.js", folder / "cases.js")
    done = subprocess.run(
        ["semgrep", "scan", "--config", str(LOCATORS / "sink-locator-v1-javascript.yaml"),
         "--json", "--quiet", "--metrics=off", "--disable-version-check", "cases.js"],
        cwd=folder, capture_output=True, text=True, encoding="utf-8", check=False,
    )
    reported = {result["start"]["line"] for result in json.loads(done.stdout)["results"]}
    wrong, total = [], 0
    lines = (folder / "cases.js").read_text(encoding="utf-8").splitlines()
    for number, line in enumerate(lines, 1):
        expected = line.rstrip().endswith("// locate")
        if not expected and not line.rstrip().endswith("// skip"):
            continue
        total += 1
        if expected != (number in reported):
            wrong.append((number, line.split("(")[0].replace("function ", "")))
    print(f"{total - len(wrong)}/{total} cases as expected; wrong: {wrong}")
    return 1 if wrong else 0


if __name__ == "__main__":
    sys.exit(main())
