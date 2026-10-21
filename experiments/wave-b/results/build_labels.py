"""Wave B: label table for the 60 non-CVE CodeQL alerts and aggregation by mechanism family.

Usage: build_labels.py DATA_DIR ROOT_CAUSES_JSON [--redact]
Inputs (DATA_DIR): wave_b_codeql_alerts.csv, mlflow_cwe22_labels.csv (verified mlflow labels).
Outputs (DATA_DIR): wave_b_labels.csv, wave_b_label_summary.json.
--redact uses the redacted evidence from ROOT_CAUSES_JSON (for the public repository).
"""

import csv
import json
import os
import sys
from collections import Counter, defaultdict

out, rc_path = sys.argv[1:3]
redact = "--redact" in sys.argv
spec = json.load(open(rc_path))
RC, SINKS = spec["root_causes"], spec["sinks"]
REPO = {
    "GHSA-42h5-h8qh-vv9v": "mlflow/mlflow",
    "GHSA-fvgf-6h6h-3322": "django/django",
    "GHSA-6jrf-rcjf-245r": "dgtlmoon/changedetection.io",
}

mlflow = {
    r["sink_location"]: r
    for r in csv.DictReader(open(os.path.join(out, "mlflow_cwe22_labels.csv")))
}
alerts = defaultdict(dict)
for r in csv.DictReader(open(os.path.join(out, "wave_b_codeql_alerts.csv"))):
    alerts[(r["pair_id"], r["cwe"], r["sink_location"])][r["version"]] = r

rows = []
for (pair, cwe, sink), by_version in sorted(alerts.items()):
    first = next(iter(by_version.values()))
    if sink in mlflow:
        m = mlflow[sink]
        rc_id, label, verification = m["root_cause_id"], m["proposed_label"], m["verification"]
        evidence = m["label_evidence"] + " | " + m["verification_evidence"]
    else:
        rc_id = SINKS[sink]
        label, verification, evidence = RC[rc_id]["label"], "verified", RC[rc_id]["label_evidence"]
    if redact and rc_id in spec["redacted_evidence"]:
        evidence = spec["redacted_evidence"][rc_id]
    rc = RC[rc_id]
    scope = "production" if first["scope"] == "production" else "test"
    technical = label
    if scope == "test":
        label = "test_code"
    decisions = sorted({v["v02_decision"] for v in by_version.values()})
    rows.append(
        dict(
            pair_id=pair,
            repository=REPO[pair],
            cwe=cwe,
            sink_location=sink,
            function=first["function"],
            scope=scope,
            occurs_in="+".join(sorted(by_version)),
            manual_label=label,
            technical_label=technical,
            root_cause_id=rc_id,
            mechanism_family=rc["mechanism_family"],
            label_note=rc["label_note"],
            evidence_type=rc["evidence_type"],
            label_evidence=evidence,
            verification=verification,
            v02_decision="/".join(decisions),
            review_status=rc["review_status"],
            labeler_blind_to_v02="no",
        )
    )
assert len(rows) == 60, len(rows)
with open(os.path.join(out, "wave_b_labels.csv"), "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)

KIND = {"false_positive": "FP", "true_positive": "TP", "TP_conditional": "TP"}


def outcome(row):
    kind = KIND.get(row["technical_label"])
    if kind is None:
        return "unknown"
    removed = "proposed_reject" in row["v02_decision"]
    return f"{kind} " + ({"FP": "removed", "TP": "lost"}[kind] if removed else "kept")


summary = {}
for scope in ("production", "test"):
    sub = [r for r in rows if r["scope"] == scope]
    repos = sorted({r["repository"] for r in sub})
    summary[scope] = {
        "alerts": len(sub),
        "labels": dict(Counter(r["technical_label"] for r in sub)),
        "root_causes": len({r["root_cause_id"] for r in sub}),
        "by_repo": {
            repo: dict(Counter(r["technical_label"] for r in sub if r["repository"] == repo))
            for repo in repos
        },
        "v02": dict(Counter(outcome(r) for r in sub)),
    }
families = defaultdict(
    lambda: {"alerts": 0, "production": 0, "repos": set(), "rcs": set(), "v02_removed": 0}
)
for r in rows:
    fam = families[r["mechanism_family"]]
    fam["alerts"] += 1
    fam["production"] += r["scope"] == "production"
    fam["repos"].add(r["repository"].split("/")[-1])
    fam["rcs"].add(r["root_cause_id"])
    fam["v02_removed"] += "proposed_reject" in r["v02_decision"]
summary["families"] = {
    name: {**v, "repos": sorted(v["repos"]), "rcs": sorted(v["rcs"])}
    for name, v in sorted(families.items())
}
with open(os.path.join(out, "wave_b_label_summary.json"), "w") as f:
    json.dump(summary, f, indent=1)
print(json.dumps({k: summary[k] for k in ("production", "test")}, indent=1))
