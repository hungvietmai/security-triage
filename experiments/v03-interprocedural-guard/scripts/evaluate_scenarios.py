"""Score one contract scenario of the expectations table against SARIF results (SPEC §8).

Per case: d / b / t = the default query / v0.2 / the v0.3 VARIANT (v03 strict, v03s scoped) reports
an alert in the case's function.
  UNSOUND  expected keep, but v0.3 drops what v0.2 reports, or (escape, contract-forbids) what
           the default reports
  VACUOUS  expected keep for an escape, but the default does not report the case
  MISSED   expected may, still reported by v0.3 (acceptable)
  ok       otherwise
Writes scenario_<SCENARIO>_<VARIANT>.json next to the first SARIF; exits 1 on UNSOUND or VACUOUS.
Usage: evaluate_scenarios.py EXPECTATIONS_CSV SCENARIO VARIANT CEX_SRC_DIR SARIF [SARIF ...]
"""

import ast
import collections
import csv
import json
import os
import sys

table, scenario, variant, src, sarifs = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5:]
funcs = []  # (file, name, first line, last line)
for fn in sorted(os.listdir(src)):
    if fn.endswith(".py"):
        with open(os.path.join(src, fn)) as f:
            tree = ast.parse(f.read())
        funcs += [(fn, n.name, n.lineno, n.end_lineno) for n in tree.body if isinstance(n, ast.FunctionDef)]
hits = collections.defaultdict(set)  # variant -> functions with an alert
for path in sarifs:
    with open(path) as f:
        results = json.load(f)["runs"][0]["results"]
    for r in results:
        loc = r["locations"][0]["physicalLocation"]
        uri, line = loc["artifactLocation"]["uri"], loc["region"]["startLine"]
        for file, name, first, last in funcs:
            if uri.endswith(file) and first <= line <= last:
                hits[r["ruleId"].split("/")[-1]].add(name)
with open(table) as f:
    expected = [r for r in csv.DictReader(f) if r["scenario"] == scenario]
rows, counts = [], collections.Counter()
for e in expected:
    c = e["case"]
    d, b, t = (c in hits[v] for v in ("none", "all", variant))
    danger = e["reason"] in ("escape", "contract-forbids")
    if e["expected"] == "keep" and ((b and not t) or (danger and d and not t)):
        v = "UNSOUND"
    elif e["expected"] == "keep" and e["reason"] == "escape" and not d:
        v = "VACUOUS"
    elif e["expected"] == "may" and t:
        v = "MISSED"
    else:
        v = "ok"
    counts[v] += 1
    rows.append((c, e["expected"], e["reason"], d, b, t, v))
print(f"== {scenario} / {variant}: {dict(counts)}")
for c, exp, why, d, b, t, v in rows:
    if v != "ok" or exp == "may":
        flags = "".join("Y" if x else "-" for x in (d, b, t))
        print(f"  {c:14} {exp:4} {why:16} default/v02/v03={flags}  {v}")
out = os.path.join(os.path.dirname(sarifs[0]), f"scenario_{scenario}_{variant}.json")
with open(out, "w") as f:
    json.dump({"scenario": scenario, "variant": variant, "counts": dict(counts), "rows": rows}, f, indent=1)
sys.exit(1 if counts["UNSOUND"] or counts["VACUOUS"] else 0)
