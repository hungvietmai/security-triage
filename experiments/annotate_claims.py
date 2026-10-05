"""Lossless rule-claim annotation over checksum-verified recorded SARIF; no rescanning."""

import argparse
import copy
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_BACKEND = _ROOT / "backend"
for _IMPORT_ROOT in (_ROOT, _BACKEND):
    if str(_IMPORT_ROOT) not in sys.path:
        sys.path.insert(0, str(_IMPORT_ROOT))

from app.scanners.sarif import sarif_findings
from experiments.run_pilot import ROOT, digest, write_json

DEFAULT_MAPPING = ROOT / "experiments/mappings/rule-claims-v1.json"


def mapping_digest(mapping):
    return hashlib.sha256(
        json.dumps(mapping, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def canonical_cwes(values):
    result = set()
    for value in values:
        match = re.fullmatch(r"cwe-(\d+)", value, re.IGNORECASE)
        if match and int(match[1]) > 0:
            result.add("CWE-" + str(int(match[1])))
    return sorted(result, key=lambda s: int(s[4:]))


def annotate(findings, config, mapping):
    """Rule claims are additive metadata; original labels and raw results survive."""
    result = []
    for original in findings:
        row = copy.deepcopy(original)
        tool, rid = row.get("tool"), row.get("rule_id")
        matches = []
        for rule in mapping["rules"]:
            if rule["tool"] != tool or not isinstance(rid, str):
                continue
            id_matches = rid == rule["rule_id"] or (
                tool == "semgrep" and rid.endswith("." + rule["rule_id"])
            )
            if not id_matches or config.get(tool + "_version") != rule["tool_version"]:
                continue
            if tool == "semgrep":
                pinned = any(
                    r.get("sha256") == rule["definition_sha256"]
                    for r in config.get("semgrep_rules", [])
                )
            else:
                pinned = (
                    config.get("codeql_query_sha256", {}).get(rule["query_path"])
                    == rule["definition_sha256"]
                )
            if pinned:
                matches.append(rule)
        rule = matches[0] if len(matches) == 1 else None
        reported = canonical_cwes(row.get("reported_cwes", []))
        mapped = rule["mapped_cwes"] if rule else []
        row["rule_semantics"] = {
            "mapping_version": mapping["version"],
            "mapping_sha256": mapping_digest(mapping),
            "status": "mapped" if rule else "unmapped",
            "canonical_rule_id": rule["rule_id"] if rule else None,
            "claim_kind": rule["claim_kind"] if rule else "unknown",
            "upstream_subcategory": rule["upstream_subcategory"] if rule else None,
            "focus_role_hint": rule["focus_role_hint"] if rule else None,
            "reported_cwes_normalized": reported,
            "mapped_rule_cwes": mapped,
            "cwe_links": {
                c: "https://cwe.mitre.org/data/definitions/" + c[4:] + ".html"
                for c in canonical_cwes(reported + mapped)
            },
            "candidate_status": "cwe78_candidate"
            if rule and "CWE-78" in mapped
            else "classification_unresolved",
            "automatic_suppression": False,
        }
        result.append(row)
    return result


def build(run_dir, mapping):
    report_path, config_path = run_dir / "run.json", run_dir / "config.json"
    report, config = (
        json.loads(report_path.read_text()),
        json.loads(config_path.read_text()),
    )
    expected = report.get("configuration_sha256", report.get("config_sha256"))
    if not expected or digest(config_path) != expected:
        raise ValueError("Configuration digest mismatch or missing provenance")
    snapshot = report.get("snapshot_sha256", report.get("manifest_sha256"))
    if not snapshot:
        raise ValueError("Snapshot identity missing")
    findings, runs = [], {}
    for tool in config["scanners"]:
        step = report.get("steps", {}).get(tool, {})
        sarif = run_dir / (tool + ".sarif")
        runs[tool] = {"status": step.get("status", "not_run"), "raw_findings": None}
        if not sarif.exists():
            if step.get("status") == "completed":
                raise ValueError("Completed scanner is missing SARIF: " + tool)
            continue
        if not step.get("sarif_sha256") or digest(sarif) != step["sarif_sha256"]:
            raise ValueError("SARIF digest mismatch or missing provenance: " + tool)
        rows, complete = sarif_findings(sarif, tool, snapshot)
        findings.extend(rows)
        runs[tool].update(raw_findings=len(rows), sarif_complete=complete)
    annotated = annotate(findings, config, mapping)
    return {
        "schema_version": 1,
        "source_run_sha256": digest(report_path),
        "source_config_sha256": expected,
        "snapshot_id": snapshot,
        "case_id": report.get("case_id"),
        "source_status": report.get("status"),
        "mapping_version": mapping["version"],
        "mapping_sha256": mapping_digest(mapping),
        "scanner_runs": runs,
        "raw_count": len(findings),
        "annotated_count": len(annotated),
        "counts_by_claim": dict(
            Counter(r["rule_semantics"]["claim_kind"] for r in annotated)
        ),
        "counts_by_candidate_status": dict(
            Counter(r["rule_semantics"]["candidate_status"] for r in annotated)
        ),
        "automatic_suppressions": 0,
        "metrics": None,
        "findings": annotated,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run-directory", type=Path, required=True)
    p.add_argument("--mapping", type=Path, default=DEFAULT_MAPPING)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    if args.output.exists():
        p.error("Use a new output path")
    result = build(args.run_directory, json.loads(args.mapping.read_text()))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_json(args.output, result)
    print(
        json.dumps(
            {
                k: result[k]
                for k in ("raw_count", "annotated_count", "automatic_suppressions")
            }
        )
    )


if __name__ == "__main__":
    main()
