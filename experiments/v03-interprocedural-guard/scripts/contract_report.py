"""Per-alert contract report for run_dev.sh (SPEC §8 criterion 3, contract coverage).

For every CWE-22 sink location that v0.2 reports: whether an allowed root was found (and its
source), whether containment is proven, whether v0.3 strict (v03) and scoped (v03s) suppress it,
and its wave B label. A suppressed alert that is not labelled false_positive, or any suppressed
RC-M1 alert (SPEC_RESOURCE §6), fails the run. Counts
are given over all alerts, so coverage is visible: a high share of correct suppressions among a
few eligible alerts is not a reduction over the whole set. When a wave B SARIF is present, the
default / v0.2 CWE-22 results of this run are compared with it (query identity).
Usage: contract_report.py WORK_DIR WAVE_B_LABELS_CSV
"""

import collections
import csv
import json
import os
import sys

W, labels_csv = sys.argv[1:]
with open(labels_csv) as f:
    labels = {r["sink_location"]: r for r in csv.DictReader(f) if r["cwe"] == "CWE-22"}


def results(path, variants):
    with open(path) as f:
        rs = json.load(f)["runs"][0]["results"]
    out = collections.Counter()
    for r in rs:
        _, cwe, v = r["ruleId"].split("/")
        if cwe == "cwe-22" and v in variants:
            loc = r["locations"][0]["physicalLocation"]
            reg = loc["artifactLocation"]["uri"], loc["region"]["startLine"], loc["region"].get("startColumn")
            out[(v, *reg, r["message"]["text"])] += 1
    return out


fail = 0
for repo in ("mlflow", "django", "bp"):
    d = os.path.join(W, repo)
    if not os.path.isdir(d):
        continue
    modes = ("v03", "v03s")
    alerts = {v: {f"{k[1]}:{k[2]}:{k[3]}" for k in results(f"{d}/all.sarif", (v,))} for v in ("none", "all", *modes)}
    rows = collections.defaultdict(lambda: {"allowed": set(), "contained": set()})
    with open(f"{d}/V03Contracts.csv") as f:
        for r in csv.DictReader(f):
            rows[f"{r['file']}:{r['line']}:{r['col']}"][r["kind"]].add(f"{r['root']} ({r['detail']})")
    print(f"== {repo}: CWE-22 sink locations default={len(alerts['none'])} v0.2={len(alerts['all'])}"
          f" v0.3 strict={len(alerts['v03'])} scoped={len(alerts['v03s'])}")
    c = collections.Counter()
    for loc in sorted(alerts["all"]):
        lab = labels.get(loc, {})
        label = lab.get("technical_label", "-")
        allowed, contained = rows[loc]["allowed"], rows[loc]["contained"]
        suppressed = [m for m in modes if loc not in alerts[m]]
        c["alerts"] += 1
        c["allowed root found" if allowed else "no allowed root"] += 1
        c["containment proven" if contained else "containment not proven"] += 1
        for m in suppressed:
            c[f"suppressed by {m} ({label})"] += 1
            if label != "false_positive" or lab.get("root_cause_id") == "RC-M1":
                fail += 1
        if allowed or contained or suppressed:
            state = "SUPPRESSED by " + "+".join(suppressed) if suppressed else "kept"
            print(f"  {loc}  label={label} {lab.get('root_cause_id', '')}  allowed={sorted(allowed) or '-'}"
                  f"  contained={sorted(contained) or '-'}  {state}")
    print("  counts:", dict(c))
    kept_risky = [loc for loc in alerts["all"] if labels.get(loc, {}).get("technical_label") in ("true_positive", "unknown")]
    for m in modes:
        print(f"  TP/unknown alerts kept by {m}: {sum(loc in alerts[m] for loc in kept_risky)}/{len(kept_risky)}")
    with open(f"{d}/V03Resources.csv") as f:
        for r in csv.DictReader(f):
            if not any(t in r["file"] for t in ("/test", "tests/")):
                print(f"  resource candidate {r['file']}:{r['name']} = {r['root']}: {r['detail']}")
    wb = f"{d}/wave_b_v02.sarif"
    if os.path.exists(wb):
        same = results(f"{d}/all.sarif", ("none", "all")) == results(wb, ("none", "all"))
        print(f"  CWE-22 default+v0.2 results vs wave B SARIF: {'identical' if same else 'DIFFERENT'}")
        fail += not same
sys.exit(1 if fail else 0)
