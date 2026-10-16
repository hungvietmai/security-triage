"""Case-level (test case, CWE) evaluation of Semgrep/CodeQL/Bandit on BenchmarkPython 0.1.
A tool flags a case when it reports, inside that test file, an alert whose rule maps to the case CWE
(OWASP Benchmark scoring convention). Only the requested split is reported."""

import collections
import json
import re
import sys

OUT = sys.argv[1]
SPLIT = sys.argv[2] if len(sys.argv) > 2 else "development"
split = json.load(open(f"{OUT}/split.json"))["cases"]
CWES = [22, 78, 79, 643]
FILE_RE = re.compile(r"testcode/(BenchmarkTest\d+)\.py$")


def tag_cwes(tags):
    ids = set()
    for t in tags or []:
        m = re.search(r"cwe[-/](\d+)", str(t), re.I)
        if m:
            ids.add(int(m.group(1)))
    return ids


def sarif_alerts(path, rule_cwe=None):
    run = json.load(open(path))["runs"][0]
    rules = {}
    for comp in [run["tool"]["driver"]] + run["tool"].get("extensions", []):
        for r in comp.get("rules", []):
            rules[r["id"]] = tag_cwes((r.get("properties") or {}).get("tags"))
    alerts = []
    for res in run["results"]:
        loc = res["locations"][0]["physicalLocation"]
        uri = loc["artifactLocation"]["uri"]
        line = loc.get("region", {}).get("startLine")
        rid = res["ruleId"]
        cwes = rule_cwe(rid) if rule_cwe else rules.get(rid, set())
        alerts.append(
            dict(uri=uri, line=line, rule=rid, cwes=cwes, flow=bool(res.get("codeFlows")))
        )
    return alerts


sem_rules = {
    r["id"]: (set(r["cwe"]), r["mode"]) for r in json.load(open(f"{OUT}/semgrep_rules.json"))
}
semgrep = sarif_alerts(f"{OUT}/semgrep.sarif", lambda rid: sem_rules[rid.split(".")[-1]][0])
for a in semgrep:
    a["mode"] = sem_rules[a["rule"].split(".")[-1]][1]
codeql = sarif_alerts(f"{OUT}/codeql.sarif")
bandit = [
    dict(
        uri=r["filename"],
        line=r["line_number"],
        rule=r["test_id"],
        cwes={r["issue_cwe"]["id"]},
        flow=False,
    )
    for r in json.load(open(f"{OUT}/bandit.json"))["results"]
]


def flagged(alerts):
    hit = collections.defaultdict(list)
    for a in alerts:
        m = FILE_RE.search(a["uri"])
        if not m or m.group(1) not in split:
            continue
        case = split[m.group(1)]
        if case["cwe"] in a["cwes"]:
            hit[m.group(1)].append(a)
    return hit


S, Q, B = flagged(semgrep), flagged(codeql), flagged(bandit)
cases = {k: v for k, v in split.items() if v["split"] == SPLIT}


def metrics(flag, subset):
    tp = sum(1 for k, v in subset.items() if v["expected_vulnerable"] and k in flag)
    fn = sum(1 for k, v in subset.items() if v["expected_vulnerable"] and k not in flag)
    fp = sum(1 for k, v in subset.items() if not v["expected_vulnerable"] and k in flag)
    tn = sum(1 for k, v in subset.items() if not v["expected_vulnerable"] and k not in flag)
    p = tp / (tp + fp) if tp + fp else None
    r = tp / (tp + fn) if tp + fn else None
    fpr = fp / (fp + tn) if fp + tn else None
    f1 = 2 * tp / (2 * tp + fp + fn) if tp + fp + fn else None
    return dict(TP=tp, FP=fp, FN=fn, TN=tn, precision=p, recall=r, F1=f1, FPR=fpr)


report = {"split": SPLIT, "per_cwe": {}, "cells": {}, "lists": {}}
for cwe in CWES + ["all"]:
    sub = {k: v for k, v in cases.items() if cwe == "all" or v["cwe"] == cwe}
    U = set(S) | set(Q)
    both = set(S) & set(Q)
    report["per_cwe"][str(cwe)] = {
        "n_true": sum(v["expected_vulnerable"] for v in sub.values()),
        "n_safe": sum(not v["expected_vulnerable"] for v in sub.values()),
        "A_semgrep": metrics(S, sub),
        "B_codeql": metrics(Q, sub),
        "C_union": metrics(U, sub),
        "AND_both": metrics(both, sub),
        **(
            {"bandit": metrics(B, sub), "union_with_bandit": metrics(U | set(B), sub)}
            if cwe in (78,)
            else {}
        ),
    }
    cells = collections.Counter()
    lists = collections.defaultdict(list)
    for k, v in sub.items():
        who = (
            "both"
            if k in S and k in Q
            else "semgrep_only"
            if k in S
            else "codeql_only"
            if k in Q
            else "neither"
        )
        lab = "true" if v["expected_vulnerable"] else "safe"
        cells[f"{who}/{lab}"] += 1
        lists[f"{who}/{lab}"].append(k)
    report["cells"][str(cwe)] = dict(cells)
    if cwe != "all":
        report["lists"][str(cwe)] = {k: sorted(v) for k, v in lists.items()}
# alerts detail for dev cases (for root-cause review)
report["alerts"] = {
    k: {
        "semgrep": [(a["rule"].split(".")[-1], a["line"], a["mode"]) for a in S.get(k, [])],
        "codeql": [(a["rule"], a["line"], a["flow"]) for a in Q.get(k, [])],
        "bandit": [(a["rule"], a["line"]) for a in B.get(k, [])],
    }
    for k in cases
}
json.dump(report, open(f"{OUT}/pilot_{SPLIT}.json", "w"), indent=1)


def fmt(x):
    return "—" if x is None else f"{x:.2f}"


for cwe in CWES + ["all"]:
    pc = report["per_cwe"][str(cwe)]
    print(f"\n== CWE-{cwe}: {pc['n_true']} true / {pc['n_safe']} safe")
    for name in ["A_semgrep", "B_codeql", "C_union", "AND_both", "bandit", "union_with_bandit"]:
        if name in pc:
            m = pc[name]
            print(
                f"  {name:18} TP={m['TP']:3} FP={m['FP']:3} FN={m['FN']:3} TN={m['TN']:3}  "
                f"P={fmt(m['precision'])} R={fmt(m['recall'])} F1={fmt(m['F1'])} "
                f"FPR={fmt(m['FPR'])}"
            )
    c = report["cells"][str(cwe)]
    print(
        "  cells:",
        {
            k: c.get(k, 0)
            for k in [
                f"{w}/{lab}"
                for w in ["semgrep_only", "codeql_only", "both", "neither"]
                for lab in ["true", "safe"]
            ]
        },
    )
