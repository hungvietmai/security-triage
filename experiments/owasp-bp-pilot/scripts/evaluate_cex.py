"""Score evidence variants on the counterexample suite.

Each fixture function is named `<mech>_<id>_bad` (must stay reported) or `<mech>_<id>_good`
(safe, may be suppressed). For each version, compare the default query (variant `none`) with
the variant `all`:
  UNSOUND   bad function reported by default but suppressed by the evidence  (must be zero)
  VACUOUS   bad function not reported even by default (test does not exercise the evidence)
  MISSED    good function still reported after evidence (lost opportunity, acceptable)
  ok        expected outcome
Usage: evaluate_cex.py SRC_DIR SARIF [SARIF ...] (one SARIF per version, label = file stem)
"""

import ast
import collections
import json
import os
import sys

src = sys.argv[1]
funcs = []  # (file, name, start, end)
for fn in sorted(os.listdir(src)):
    if fn.endswith(".py"):
        tree = ast.parse(open(os.path.join(src, fn)).read())
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and (
                node.name.endswith("_bad") or node.name.endswith("_good")
            ):
                funcs.append((fn, node.name, node.lineno, node.end_lineno))


def func_at(uri, line):
    for f in funcs:
        if uri.endswith(f[0]) and f[2] <= line <= f[3]:
            return f[1]


summary = {}
for sarif in sys.argv[2:]:
    label = os.path.basename(sarif).rsplit(".", 1)[0]
    hits = collections.defaultdict(set)  # variant -> functions
    for r in json.load(open(sarif))["runs"][0]["results"]:
        variant = r["ruleId"].split("/")[-1]
        loc = r["locations"][0]["physicalLocation"]
        f = func_at(loc["artifactLocation"]["uri"], loc["region"]["startLine"])
        if f:
            hits[variant].add(f)
    rows, counts = [], collections.Counter()
    for _, name, _, _ in funcs:
        bad = name.endswith("_bad")
        d, e = name in hits["none"], name in hits["all"]
        if bad and not d:
            v = "VACUOUS"
        elif bad and d and not e:
            v = "UNSOUND"
        elif not bad and e:
            v = "MISSED"
        else:
            v = "ok"
        counts[v] += 1
        rows.append((name, "bad" if bad else "good", d, e, v))
    summary[label] = {"counts": dict(counts), "rows": rows}
    print(f"\n== {label}: {dict(counts)}")
    for r in rows:
        print(
            f"  {r[0]:24} {r[1]:4}  default={'Y' if r[2] else '-'}  "
            f"evidence={'Y' if r[3] else '-'}  {r[4]}"
        )
json.dump(
    summary, open(os.path.join(os.path.dirname(sys.argv[2]), "cex_results.json"), "w"), indent=1
)
