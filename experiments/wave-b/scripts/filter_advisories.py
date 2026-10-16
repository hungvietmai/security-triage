"""Automatic filter of SELECTION_PROTOCOL.md.

PyPI, CWE-22/643, not withdrawn, has a GitHub fix commit.
Writes every considered advisory with its decision, then the deterministic review order."""

import glob
import hashlib
import json
import re
import sys
from collections import Counter

ADB, OUT = sys.argv[1], sys.argv[2]
COMMIT = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{7,40})")
rows = []
for f in glob.glob(f"{ADB}/advisories/github-reviewed/**/*.json", recursive=True):
    d = json.load(open(f))
    pkgs = [
        a["package"]["name"]
        for a in d.get("affected", [])
        if a.get("package", {}).get("ecosystem") == "PyPI"
    ]
    if not pkgs:
        continue
    cwes = d.get("database_specific", {}).get("cwe_ids", []) or []
    if not ({"CWE-22", "CWE-643"} & set(cwes)):
        continue
    row = {
        "ghsa_id": d["id"],
        "aliases": d.get("aliases", []),
        "packages": sorted(set(pkgs)),
        "cwes": cwes,
        "published": d.get("published", "")[:10],
        "summary": d.get("summary", ""),
        "fix_commits": sorted(
            {
                m.group(0)
                for r in d.get("references", [])
                for m in [COMMIT.match(r.get("url", ""))]
                if m
            }
        ),
    }
    if d.get("withdrawn"):
        row["decision"] = "excluded:withdrawn"
    elif not row["fix_commits"]:
        row["decision"] = "excluded:no_fix_commit_reference"
    else:
        row["decision"] = "candidate"
        row["order_key"] = hashlib.sha256(
            ("security-triage/wave-b-v1/" + d["id"]).encode()
        ).hexdigest()
    rows.append(row)
rows.sort(key=lambda r: (r["decision"] != "candidate", r.get("order_key", ""), r["ghsa_id"]))
json.dump(rows, open(OUT, "w"), indent=1)

print(Counter(r["decision"] for r in rows))
print(Counter(c for r in rows for c in r["cwes"] if c in ("CWE-22", "CWE-643")))
