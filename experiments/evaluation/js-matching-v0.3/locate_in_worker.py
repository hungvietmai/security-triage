"""Run inside the worker: locator v0 (as deployed), locator v1 draft and a constant-command
trial rule on npm packages. Prints one JSON object. Sources are only parsed, never executed.

stdin: JSON {"v1": <yaml text>, "constant": <yaml text>, "sources": ["name@version", ...]}
"""

import io
import json
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

V0 = "/srv/triage/experiments/locators/sink-locator-v0-javascript.yaml"
job = json.load(sys.stdin)
work = Path(tempfile.mkdtemp())
(work / "v1.yaml").write_text(job["v1"], encoding="utf-8")
(work / "constant.yaml").write_text(job["constant"], encoding="utf-8")


def semgrep(rules, folder):
    argv = [
        "semgrep",
        "scan",
        "--config",
        str(rules),
        "--json",
        "--quiet",
        "--metrics=off",
        "--disable-version-check",
        "--disable-nosem",
        "--no-git-ignore",
        ".",
    ]
    done = subprocess.run(
        argv, cwd=folder, capture_output=True, text=True, encoding="utf-8", check=False
    )
    try:
        out = json.loads(done.stdout)
    except ValueError:
        return {"error": done.stderr[-300:]}
    rows = []
    for r in out["results"]:
        metavars = r.get("extra", {}).get("metavars", {})
        rows.append(
            {
                "rule": r["check_id"].rsplit(".", 1)[-1],
                "path": r["path"],
                "start": [r["start"]["line"], r["start"]["col"]],
                "end": [r["end"]["line"], r["end"]["col"]],
                "method": (metavars.get("$M") or {}).get("abstract_content"),
            }
        )
    return {"results": rows, "errors": len(out.get("errors", []))}


def unpack(data):
    folder = Path(tempfile.mkdtemp())
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        archive.extractall(folder, filter="data")
    return folder / "package"


result = {}
for source in job["sources"]:
    name, _, version = source.rpartition("@")
    try:
        with urllib.request.urlopen(
            f"https://registry.npmjs.org/{name}/{version}", timeout=60
        ) as r:
            meta = json.load(r)
        with urllib.request.urlopen(meta["dist"]["tarball"], timeout=120) as r:
            data = r.read()
    except Exception as error:  # noqa: BLE001
        result[source] = {"error": str(error)}
        continue
    deployed = unpack(data)
    v0 = semgrep(V0, deployed)
    controlled = unpack(data)
    for ignore in list(controlled.rglob(".semgrepignore")):
        ignore.unlink()
    (controlled / ".semgrepignore").write_text("node_modules/\n", encoding="utf-8")
    result[source] = {
        "v0_deployed": v0,
        "v0_controlled_ignore": semgrep(V0, controlled),
        "v1_controlled_ignore": semgrep(work / "v1.yaml", controlled),
        "constant": semgrep(work / "constant.yaml", controlled),
    }
    print(source, "done", file=sys.stderr, flush=True)
json.dump(result, sys.stdout)
