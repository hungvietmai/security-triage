"""Wave A: join baseline alerts -> sink location -> v0.2 evidence -> decision, one row per alert.

Inputs per project (OUT/<name>/): v02.sarif (variants st/cwe-*/none and /all), evidence.csv
(Evidence.ql table), semgrep.sarif. Baseline = variant `none` (the default CodeQL query).
A CodeQL alert is `proposed_reject` when its sink location no longer appears under `all`.
Evidence rows are attached when they lie in the same file and enclosing function as the sink;
otherwise the row records that the deciding evidence lies elsewhere (interprocedural).
Semgrep alerts are kept (F' not implemented). Scope: `production` unless the path is under
tests/, examples/, docs/ or a test_*.py file. Manual label columns are left for review.
Usage: join.py WAVE_DIR NAME COMMIT SEMGREP_RULES_JSON
"""

import ast
import csv
import json
import os
import re
import sys
from collections import defaultdict

wave, name, commit, rules_path = sys.argv[1:5]
out = os.path.join(wave, "out", name)
src = os.path.join(wave, "src", name)


def rel(uri):
    uri = uri.replace("file://", "")
    return uri.split(f"src/{name}/")[-1] if f"src/{name}/" in uri else uri.lstrip("/")


_func_cache = {}


def enclosing_function(path, line):
    if path not in _func_cache:
        spans = []
        try:
            tree = ast.parse(open(os.path.join(src, path), encoding="utf-8").read())
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    spans.append((node.lineno, node.end_lineno, node.name))
        except (SyntaxError, OSError, UnicodeDecodeError):
            pass
        _func_cache[path] = spans
    inner = [s for s in _func_cache[path] if s[0] <= line <= s[1]]
    return min(inner, key=lambda s: s[1] - s[0])[2] if inner else "<module>"


def scope(path):
    if re.search(r"(^|/)(tests?|examples?|docs?)/", path):
        return "test-or-example"
    if re.search(r"(^|/)test_[^/]*\.py$", path):
        return "test-or-example"
    return "production"


codeql = defaultdict(set)  # (cwe, variant) -> {(file, line, col)}
for r in json.load(open(os.path.join(out, "v02.sarif")))["runs"][0]["results"]:
    _, cwe, variant = r["ruleId"].split("/")
    loc = r["locations"][0]["physicalLocation"]
    region = loc["region"]
    key = (rel(loc["artifactLocation"]["uri"]), region["startLine"], region.get("startColumn", 0))
    codeql[(cwe.split("-")[1], variant)].add(key)

evidence = defaultdict(list)  # (cwe, file, function) -> rows
with open(os.path.join(out, "evidence.csv"), newline="") as f:
    for row in csv.DictReader(f):
        evidence[(row["cwe"], row["file"], row["function"])].append(row)

sem_rules = {r["id"]: (set(r["cwe"]), r["mode"]) for r in json.load(open(rules_path))}
rows = []
for cwe in ["22", "78", "79", "643"]:
    for path, line, col in sorted(codeql[(cwe, "none")]):
        kept = (path, line, col) in codeql[(cwe, "all")]
        func = enclosing_function(path, line)
        ev = evidence.get((cwe, path, func), [])
        mechs = sorted({e["mech"] for e in ev})
        detail = "; ".join(sorted({f"{e['kind']}@{e['line']}" for e in ev}))
        if not kept and not ev:
            detail = "deciding evidence outside the sink function (interprocedural)"
        rows.append(
            dict(
                repository=name,
                commit_sha=commit,
                cwe=f"CWE-{cwe}",
                file=path,
                sink_location=f"{path}:{line}:{col}",
                function=func,
                scope=scope(path),
                detected_by="codeql",
                baseline_alert="yes",
                v02_decision="keep" if kept else "proposed_reject",
                evidence_mechanism="+".join(mechs) if not kept else ("+".join(mechs) or ""),
                evidence_detail=detail if not kept else (detail or ""),
                manual_label="",
                label_evidence="",
                review_status="unreviewed",
            )
        )
for r in json.load(open(os.path.join(out, "semgrep.sarif")))["runs"][0]["results"]:
    rid = r["ruleId"].split(".")[-1]
    cwes, mode = sem_rules[rid]
    loc = r["locations"][0]["physicalLocation"]
    path, line = rel(loc["artifactLocation"]["uri"]), loc["region"]["startLine"]
    for cwe in sorted(cwes & {22, 78, 79, 643}):
        rows.append(
            dict(
                repository=name,
                commit_sha=commit,
                cwe=f"CWE-{cwe}",
                file=path,
                sink_location=f"{path}:{line}",
                function=enclosing_function(path, line),
                scope=scope(path),
                detected_by=f"semgrep:{rid}:{mode}",
                baseline_alert="yes",
                v02_decision="keep",
                evidence_mechanism="",
                evidence_detail="semgrep alert kept (F' not implemented)",
                manual_label="",
                label_evidence="",
                review_status="unreviewed",
            )
        )
fields = list(rows[0].keys()) if rows else []
with open(os.path.join(out, "alerts.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    w.writerows(rows)
summary = defaultdict(lambda: defaultdict(int))
for r in rows:
    summary[(r["cwe"], r["scope"], r["detected_by"].split(":")[0])][r["v02_decision"]] += 1
for k, v in sorted(summary.items()):
    print(name, *k, dict(v))
