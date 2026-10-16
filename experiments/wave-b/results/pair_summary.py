"""Wave B: per-pair summary after scanning (no labels).

For each pair and its study CWE (22 or 643), using the CodeQL default query (variant `none`) as the
baseline and v0.2 (`all`):
  - baseline alerts in the whole repository and in the advisory's affected files, per version;
  - the 4-cell interpretation from SELECTION_PROTOCOL.md, computed on the affected files;
  - alerts v0.2 proposes to remove, per version;
  - coverage: modelled sources / sinks of the default query inside the affected files (Coverage.ql).
Usage: pair_summary.py WAVE_B_DIR
"""

import csv
import json
import os
import re
import sys
from collections import defaultdict

import yaml

wave = sys.argv[1]
inv = yaml.safe_load(open(os.path.join(wave, "inventory.yaml")))


def affected_files(text):
    return [re.split(r"\s+\(", part.strip())[0] for part in text.split(";") if part.strip()]


def alerts(vid, cwe):
    by = defaultdict(set)
    path = os.path.join(wave, "out", vid, "v02.sarif")
    if not os.path.exists(path):
        return None
    for r in json.load(open(path))["runs"][0]["results"]:
        _, c, variant = r["ruleId"].split("/")
        if c != f"cwe-{cwe}":
            continue
        loc = r["locations"][0]["physicalLocation"]
        region = loc["region"]
        by[variant].add(
            (loc["artifactLocation"]["uri"], region["startLine"], region.get("startColumn", 0))
        )
    return by


def coverage(vid, cwe, files):
    path = os.path.join(wave, "out", vid, "coverage.csv")
    if not os.path.exists(path):
        return None
    roles = defaultdict(int)
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            if row["cwe"] == cwe and any(row["file"].endswith(a) for a in files):
                roles[row["role"]] += 1
    return dict(roles)


def in_files(keys, files):
    return {k for k in keys if any(k[0].endswith(a) for a in files)}


rows = []
for p in inv["pairs"]:
    cwe = "643" if p["stratum"] == "CWE-643" else "22"
    files = affected_files(p["affected_code"])
    row = {
        "pair_id": p["pair_id"],
        "repository": p["repository"],
        "cwe": f"CWE-{cwe}",
        "sink_class": p["sink_class"],
        "affected_files": "; ".join(files),
    }
    present = {}
    for kind in ("vulnerable", "fixed"):
        vid = f"{p['pair_id']}__{kind}"
        a = alerts(vid, cwe)
        if a is None:
            row[f"{kind}_status"] = "not_scanned"
            continue
        base, kept = a["none"], a["all"]
        local = in_files(base, files)
        present[kind] = bool(local)
        cov = coverage(vid, cwe, files) or {}
        row.update(
            {
                f"{kind}_status": "scanned",
                f"{kind}_baseline_repo": len(base),
                f"{kind}_baseline_affected": len(local),
                f"{kind}_v02_removed_repo": len(base - kept),
                f"{kind}_v02_removed_affected": len(local - kept),
                f"{kind}_sources_affected": cov.get("source", 0),
                f"{kind}_sinks_affected": cov.get("sink", 0),
            }
        )
    if len(present) == 2:
        v, f = present["vulnerable"], present["fixed"]
        row["cell"] = {
            (True, False): "detected_then_gone",
            (True, True): "still_reported_after_fix",
            (False, False): "not_detected",
            (False, True): "reported_only_after_fix",
        }[(v, f)]
        row["baseline_detected"] = "yes" if v else "no"
        row["sink_coverage"] = "yes" if row.get("vulnerable_sinks_affected") else "no"
        row["source_coverage"] = (
            "yes" if row.get("vulnerable_sources_affected") else "no (in affected files)"
        )
        row["evidence_applicable"] = (
            "yes"
            if (row.get("vulnerable_baseline_affected") or row.get("fixed_baseline_affected"))
            else "no"
        )
    rows.append(row)

fields = sorted(
    {k for r in rows for k in r}, key=lambda k: (k not in ("pair_id", "repository", "cwe"), k)
)
with open(os.path.join(wave, "out", "pair_summary.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    w.writerows(rows)
for r in rows:
    print(
        r["pair_id"],
        r["cwe"],
        r.get("cell", "-"),
        {
            k: r[k]
            for k in r
            if k.startswith(("vulnerable_", "fixed_")) and not k.endswith("status")
        },
    )
