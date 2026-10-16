"""Apply CodeQL safety evidence to the union alert set and score it (development split only).

Configurations (case-level, unit = (test case, CWE), OWASP scoring):
  A   Semgrep security rules alone
  B   CodeQL default query alone (variant `none` of the evidence queries)
  C   A ∪ B, no decision layer
  E   CodeQL with all safety evidence written into the query as sanitizers (variant `all`)
  E_m CodeQL with a single mechanism m (attribution)
  F   C + decision layer:
        - a CodeQL alert is proposed for removal when the evidence variant `all` no longer
          reports a flow in that file (same evidence as E);
        - a Semgrep alert in mode `taint` is risk evidence and is kept;
        - a Semgrep pattern (`search`) alert is removed only when CodeQL reported this case by
          default and every CodeQL flow there is removed by the evidence (case-level sink match,
          an approximation recorded in the report);
        - a Semgrep-only alert (CodeQL never reported the case) is kept: F' (negative-evidence
          filter with a CodeQL source-coverage check) is not implemented yet.
"""

import collections
import json
import re
import sys

OUT = sys.argv[1]
SPLIT = sys.argv[2] if len(sys.argv) > 2 else "development"
EVID = sys.argv[3] if len(sys.argv) > 3 else f"{OUT}/evidence.sarif"
TAG = sys.argv[4] if len(sys.argv) > 4 else ""
split = json.load(open(f"{OUT}/split.json"))["cases"]
cases = {k: v for k, v in split.items() if v["split"] == SPLIT}
FILE_RE = re.compile(r"testcode/(BenchmarkTest\d+)\.py$")
MECHS = ["constbranch", "collection", "guard", "route", "header"]


def case_of(uri):
    m = FILE_RE.search(uri)
    return m.group(1) if m and m.group(1) in cases else None


# evidence variants: st/cwe-<cwe>/<variant>
ev = collections.defaultdict(set)  # (cwe, variant) -> cases still flagged
for r in json.load(open(EVID))["runs"][0]["results"]:
    _, cwe, variant = r["ruleId"].split("/")
    cwe = int(cwe.split("-")[1])
    c = case_of(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"])
    if c and cases[c]["cwe"] == cwe:
        ev[(cwe, variant)].add(c)

sem_rules = {
    r["id"]: (set(r["cwe"]), r["mode"]) for r in json.load(open(f"{OUT}/semgrep_rules.json"))
}
sem = collections.defaultdict(list)  # case -> [mode]
for r in json.load(open(f"{OUT}/semgrep.sarif"))["runs"][0]["results"]:
    c = case_of(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"])
    rid = r["ruleId"].split(".")[-1]
    cwes, mode = sem_rules[rid]
    if c and cases[c]["cwe"] in cwes:
        sem[c].append(mode)


def flagged_by(variant):
    return {c for c in cases if c in ev[(cases[c]["cwe"], variant)]}


A = set(sem)
B = flagged_by("none")
E = flagged_by("all")
Em = {m: flagged_by(m) for m in MECHS}
decisions = {}
for c in cases:
    kept, why = [], []
    if c in B:
        if c in E:
            kept.append("codeql")
            why.append("codeql: flow remains after evidence")
        else:
            removed_by = [m for m in MECHS if c not in Em[m]] or ["combined"]
            why.append("codeql: removed by " + "+".join(removed_by))
    for mode in sem.get(c, []):
        if mode == "taint":
            kept.append("semgrep-taint")
            why.append("semgrep taint: risk evidence, keep")
        elif c in B and c not in E:
            why.append("semgrep pattern: removed, CodeQL evidence covers the case")
        elif c in B:
            kept.append("semgrep-pattern")
            why.append("semgrep pattern: CodeQL flow remains, keep")
        else:
            kept.append("semgrep-pattern")
            why.append("semgrep pattern only: kept (F' not implemented)")
    if c in A or c in B:
        decisions[c] = {"kept": bool(kept), "by": sorted(set(kept)), "reasons": why}
F = {c for c, d in decisions.items() if d["kept"]}
C = A | B


def m(flag, sub):
    tp = sum(1 for k in sub if sub[k]["expected_vulnerable"] and k in flag)
    fn = sum(1 for k in sub if sub[k]["expected_vulnerable"] and k not in flag)
    fp = sum(1 for k in sub if not sub[k]["expected_vulnerable"] and k in flag)
    tn = sum(1 for k in sub if not sub[k]["expected_vulnerable"] and k not in flag)
    return dict(
        TP=tp,
        FP=fp,
        FN=fn,
        TN=tn,
        P=round(tp / (tp + fp), 3) if tp + fp else None,
        R=round(tp / (tp + fn), 3) if tp + fn else None,
        F1=round(2 * tp / (2 * tp + fp + fn), 3) if tp + fp + fn else None,
        FPR=round(fp / (fp + tn), 3) if fp + tn else None,
    )


report = {"split": SPLIT, "per_cwe": {}, "attribution": {}, "decisions": decisions}
for cwe in [22, 78, 79, 643, "all"]:
    sub = {k: v for k, v in cases.items() if cwe == "all" or v["cwe"] == cwe}
    row = {
        "A_semgrep": m(A, sub),
        "B_codeql": m(B, sub),
        "C_union": m(C, sub),
        "E_codeql_evidence": m(E, sub),
        "F_decision": m(F, sub),
    }
    row.update({f"E_{k}": m(v, sub) for k, v in Em.items()})
    report["per_cwe"][str(cwe)] = row
    # attribution relative to B: FP removed / TP lost per single mechanism and combined
    att = {}
    for name, flag in list(Em.items()) + [("all", E)]:
        att[name] = {
            "FP_removed": sum(
                1 for k in sub if not sub[k]["expected_vulnerable"] and k in B and k not in flag
            ),
            "TP_lost": sorted(
                k for k in sub if sub[k]["expected_vulnerable"] and k in B and k not in flag
            ),
        }
    report["attribution"][str(cwe)] = att
json.dump(report, open(f"{OUT}/evidence{TAG}_{SPLIT}.json", "w"), indent=1)


def f(x):
    return "—" if x is None else f"{x:.2f}"


for cwe, row in report["per_cwe"].items():
    print(f"\n== CWE-{cwe}")
    for k in ["A_semgrep", "B_codeql", "C_union", "E_codeql_evidence", "F_decision"]:
        v = row[k]
        print(
            f"  {k:18} TP={v['TP']:3} FP={v['FP']:3} FN={v['FN']:3} TN={v['TN']:3} "
            f"P={f(v['P'])} R={f(v['R'])} F1={f(v['F1'])} FPR={f(v['FPR'])}"
        )
    print(
        "  attribution vs B:",
        {k: (a["FP_removed"], len(a["TP_lost"])) for k, a in report["attribution"][cwe].items()},
    )
    lost = report["attribution"][cwe]["all"]["TP_lost"]
    if lost:
        print("  TP lost (all):", lost)
