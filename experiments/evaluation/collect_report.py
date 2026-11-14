"""Scan one named source with the running stack and save its exported report.

The evaluation reads only what a user can export from the application: the before/after
report (JSON) and the merged SARIF log. This script requests a scan through the public API,
waits for it and stores both files, so the tables in this directory can be rebuilt without
the stack. It runs no scanner itself.

    python collect_report.py <output-dir> <profile> npm <package> <version>
    python collect_report.py <output-dir> <profile> github <owner> <repo> <commit>

Only use it on development data. Never point it at a frozen pair or a held-out source.
"""

import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

API = "http://localhost:8000/api/v1"
PROJECT_NAME = "Danh gia truoc-sau (du lieu phat trien)"
WAIT_SECONDS = 1800


def call(path, body=None):
    request = urllib.request.Request(
        API + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        sys.exit(f"HTTP {error.code} for {path}: {error.read().decode()[:600]}")


def project_id():
    found = call(f"/projects?q={urllib.request.quote(PROJECT_NAME)}&limit=1")["items"]
    return found[0]["id"] if found else call("/projects", {"name": PROJECT_NAME})["id"]


def main():
    output, profile, kind, *rest = sys.argv[1:]
    if kind == "npm":
        source = {"kind": "npm", "package": rest[0], "version": rest[1]}
    else:
        source = {"kind": "github", "owner": rest[0], "repo": rest[1], "commit": rest[2]}
    accepted = call(f"/projects/{project_id()}/scans", {"source": source, "profile": profile})
    scan_id = accepted["scan_id"]
    deadline = time.monotonic() + WAIT_SECONDS
    while (scan := call(f"/scans/{scan_id}"))["status"] in {"queued", "running"}:
        if time.monotonic() > deadline:
            sys.exit(f"scan {scan_id} still {scan['status']} after {WAIT_SECONDS} s")
        time.sleep(5)
    folder = Path(output)
    folder.mkdir(parents=True, exist_ok=True)
    manifest = {"source": source, "profile": profile, "scan_status": scan["status"], "files": {}}
    for name, path in (("report.json", "report"), ("report.sarif", "report.sarif")):
        data = (
            json.dumps(call(f"/scans/{scan_id}/{path}"), indent=2, ensure_ascii=False) + "\n"
        ).encode()
        (folder / name).write_bytes(data)
        manifest["files"][name] = hashlib.sha256(data).hexdigest()
    (folder / "manifest.json").write_bytes((json.dumps(manifest, indent=2) + "\n").encode())
    stages = json.loads((folder / "report.json").read_bytes())["stages"]
    print(scan["status"], scan["error_message"] or "", stages)


if __name__ == "__main__":
    main()
