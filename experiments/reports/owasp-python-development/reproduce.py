"""Reproduce this development report from retained run bytes and source labels.

This is report-specific reconciliation, not a general sink matcher or a triage
policy. No target code is imported/executed. Unmatched findings remain explicit.
"""

import argparse
import ast
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from experiments.run_pilot import digest, sarif_findings, verify_source_identity  # noqa: E402


def require(condition, message):
    if not condition:
        raise ValueError(message)


def span(node):
    # Reviewed expressions are ASCII; AST byte offsets equal SARIF codepoints.
    return {"startLine": node.lineno, "startColumn": node.col_offset + 1,
            "endLine": node.end_lineno, "endColumn": node.end_col_offset + 1}


def inside(region, anchor):
    if not region or "startLine" not in region:
        return False
    start = (region["startLine"], region.get("startColumn", 1))
    end = (region.get("endLine", region["startLine"]), region.get("endColumn", start[1]))
    return (anchor["startLine"], anchor["startColumn"]) <= start <= end <= (
        anchor["endLine"], anchor["endColumn"])


def build(run_dir, labels_path, expectations_path):
    run = json.loads((run_dir / "run.json").read_text())
    case = json.loads((run_dir / "case.json").read_text())
    config = json.loads((run_dir / "config.json").read_text())
    labels = json.loads(labels_path.read_text())
    expected = json.loads(expectations_path.read_text())
    require(run["status"] == "completed", "Both scans must have completed")
    for filename, key in [("case.json", "case_manifest_sha256"),
                          ("config.json", "configuration_sha256"),
                          ("source.tgz", "snapshot_sha256")]:
        require(digest(run_dir / filename) == run[key], "Run byte mismatch: " + filename)
    require(run["snapshot_sha256"] == case["artifact_sha256"], "Snapshot mismatch")
    require(labels["source_commit"] == expected["source_commit"] == case["source_commit"],
            "Label/source revision mismatch")
    source = run_dir / "source" / case["archive_root"]
    verify_source_identity(case, source)
    for relative, expected_hash in labels["context_files_sha256"].items():
        require(digest(source / relative) == expected_hash, "Review context mismatch: " + relative)
    require(digest(source / "expectedresults-0.1.csv") == expected["expected_results_sha256"],
            "Upstream expectation mismatch")
    expected_by_id = {x["test_id"]: x for x in expected["cases"]}
    require(len(expected_by_id) == len(expected["cases"]) == len(labels["units"]) == 20,
            "All 20 preselected cases required")
    require({x["test_id"] for x in labels["units"]} == set(expected_by_id), "Case mismatch")
    rows = []
    for tool in config["scanners"]:
        sarif = run_dir / (tool + ".sarif")
        require(digest(sarif) == run["steps"][tool]["sarif_sha256"], "SARIF byte mismatch")
        findings, complete = sarif_findings(sarif, tool, case["artifact_sha256"])
        require(complete, "Partial SARIF")
        rows.extend(findings)
    require(rows == json.loads((run_dir / "findings.json").read_text()), "Raw ledger mismatch")
    units, by_path = [], {}
    for label in labels["units"]:
        require(label["scope_verdict"] == "in_scope" and label["technical_verdict"] in
                {"true_positive", "false_positive"}, "This report requires resolved source labels")
        exp = expected_by_id[label["test_id"]]
        require(label["path"] == exp["path"], "Expectation path mismatch")
        path = source / label["path"]
        require(digest(path) == label["source_sha256"] == exp["source_sha256"], "Source mismatch")
        calls = [n for n in ast.walk(ast.parse(path.read_text()))
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                 and isinstance(n.func.value, ast.Name) and n.func.value.id == "subprocess"
                 and n.func.attr == "run"]
        require(len(calls) == 1, "Expected one reviewed subprocess sink: " + str(path))
        anchor = span(calls[0])
        identity = [case["artifact_sha256"], label["path"], anchor, "shell_command"]
        unit_id = "sink:" + hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
        unit = {**label, "unit_id": unit_id, "snapshot_id": case["artifact_sha256"],
                "sink_anchor": anchor, "argument_role": "shell_command",
                "upstream_expected_vulnerable": exp["expected_vulnerable"], "raw_ids": []}
        units.append(unit)
        by_path[label["path"]] = unit
    unmatched, outside = [], []
    for row in rows:
        unit = by_path.get(row["reported_path"])
        if unit is None:
            outside.append(row)
        elif inside(row["reported_region"], unit["sink_anchor"]):
            unit["raw_ids"].append(row["raw_id"])
            row["reviewed_unit_id"] = unit["unit_id"]
        else:
            unmatched.append(row)
    require(len(rows) == sum(len(u["raw_ids"]) for u in units) + len(unmatched) + len(outside),
            "Reconciliation lost a raw finding")
    predicted = {t: {r["reviewed_unit_id"] for r in rows
                     if r["tool"] == t and "reviewed_unit_id" in r} for t in config["scanners"]}
    predicted["semgrep_without_audit_diagnostic"] = {
        r["reviewed_unit_id"] for r in rows if r["tool"] == "semgrep"
        and not r["rule_id"].endswith(".subprocess-shell-true") and "reviewed_unit_id" in r}
    predicted["simple_union_diagnostic"] = predicted["semgrep"] | predicted["codeql"]
    positive = {u["unit_id"] for u in units if u["technical_verdict"] == "true_positive"}
    negative = {u["unit_id"] for u in units if u["technical_verdict"] == "false_positive"}
    counts = {name: {"TP": len(p & positive), "FP": len(p & negative), "FN": len(positive - p),
                     "detected_locations": len(p)} for name, p in predicted.items()}
    s, q = predicted["semgrep"], predicted["codeql"]
    partition = {"semgrep_only": s - q, "codeql_only": q - s, "both": s & q,
                 "neither_known_positive": positive - (s | q)}
    return {"report_version": 1, "configuration_commit": run["configuration_commit"],
            "source_commit": case["source_commit"], "split": "development",
            "review_status": "single unblinded assistant review; second review pending",
            "labels_sha256": digest(labels_path), "expectations_sha256": digest(expectations_path),
            "raw_counts": dict(Counter(r["tool"] for r in rows)),
            "descriptive_location_counts": counts,
            "partition": {k: {"TP": len(v & positive), "FP": len(v & negative),
                              "unit_ids": sorted(v)} for k, v in partition.items()},
            "stage_seconds": {k: v["seconds"] for k, v in run["steps"].items()},
            "units": units, "raw_findings": rows,
            "unmatched_target_findings": unmatched, "outside_target_findings": outside,
            "ST": "not_implemented", "S1": "not_implemented", "effectiveness_claim": None}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    result = build(args.run, here / "source-labels.json",
                   here.parents[1] / "labels/owasp-python-cwe78-expectations.json")
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps(result["descriptive_location_counts"], indent=2))
