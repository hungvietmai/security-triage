"""Run pinned R1 source fixtures through both scanners and priority v0.1."""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parents[2]
for _IMPORT_ROOT in (_ROOT, _ROOT / "backend"):
    if str(_IMPORT_ROOT) not in sys.path:
        sys.path.insert(0, str(_IMPORT_ROOT))
from app.scanners.pipeline import run_pipeline
from app.scanners.provenance import digest
from app.triage.claims import classify_claims
from app.triage.evidence import build_evidence
from app.triage.policy import apply_policy, validate_policy
from app.triage.reconcile import reconcile_findings

from experiments.run_pilot import (
    CLAIMS_FILE,
    POLICY_FILE,
    ROOT,
    _assert_finding_conservation,
    _locate_sinks,
    _verified_definitions,
    write_json,
)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--semgrep", default="semgrep")
    parser.add_argument("--codeql", default="codeql")
    parser.add_argument("--javascript-query-pack", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    source = ROOT / "experiments/fixtures/r1-feasibility"
    manifest = json.loads((source / "manifest.json").read_text())
    for case in manifest["cases"]:
        if digest(source / case["file"]) != case["source_sha256"]:
            raise ValueError("R1 source digest mismatch: " + case["file"])
    for path, sha in manifest["support_files"].items():
        if digest(source / path) != sha:
            raise ValueError("R1 support digest mismatch: " + path)
    config = json.loads(
        (ROOT / "experiments/configs/development-batch-01-upstream.json").read_text()
    )
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    result = run_pipeline(
        scanners=config["scanners"],
        language="javascript",
        source=source,
        output=output,
        snapshot_sha256=digest(source / "manifest.json"),
        repository_root=ROOT,
        semgrep_binary=args.semgrep,
        codeql_binary=args.codeql,
        semgrep_version=config["semgrep_version"],
        codeql_version=config["codeql_version"],
        semgrep_rules=config["semgrep_rules"],
        codeql_queries=config["codeql_queries"],
        codeql_query_sha256=config["codeql_query_sha256"],
        javascript_query_pack=args.javascript_query_pack,
        python_query_pack=None,
        jobs=config["jobs"],
        timeout_seconds=config["timeout_seconds"],
        codeql_ram_mb=2048,
    )
    if result.status != "completed":
        raise RuntimeError("R1 scanner run incomplete: " + str(result.steps))
    files = [case["file"] for case in manifest["cases"]] + list(
        manifest["support_files"]
    )
    sinks, sources, locator = _locate_sinks(
        language="javascript",
        source=source,
        output=output,
        source_files=files,
        semgrep_binary=args.semgrep,
        jobs=config["jobs"],
        timeout_seconds=config["timeout_seconds"],
    )
    units = reconcile_findings(result.findings, sinks, sources)
    _assert_finding_conservation(result.findings, units)
    mapping = json.loads(CLAIMS_FILE.read_text())
    policy = validate_policy(yaml.safe_load(POLICY_FILE.read_text()))
    claims = classify_claims(
        mapping, result.findings, _verified_definitions(config, output, result)
    )
    assessments = [
        apply_policy(build_evidence(u, result.findings, claims, sinks, sources), policy)
        for u in units
    ]
    by_case = {}
    for case in manifest["cases"]:
        tiers = [
            a["priority"]
            for u, a in zip(units, assessments, strict=True)
            if u["path"] == case["file"]
        ]
        by_case[case["case_id"]] = {
            "findings": sum(
                f["reported_path"] == case["file"] for f in result.findings
            ),
            "units": len(tiers),
            "tiers": tiers,
        }
    write_json(output / "findings.json", result.findings)
    write_json(output / "units.json", units)
    write_json(output / "assessments.json", assessments)
    write_json(
        output / "r1-summary.json",
        {
            "by_case": by_case,
            "steps": result.steps,
            "locator": locator,
            "counts": dict(Counter(a["priority"] for a in assessments)),
        },
    )
    print(json.dumps(by_case, sort_keys=True))
    for number in ("01", "04", "09"):
        case = next(v for k, v in by_case.items() if k.startswith(number + "-"))
        if "P1" in case["tiers"]:
            raise RuntimeError("Literal R1 fixture unexpectedly reached P1: " + number)
    for number in ("03", "05"):
        case = next(v for k, v in by_case.items() if k.startswith(number + "-"))
        if not case["units"] or any(t not in {"P1", "P2", "P3"} for t in case["tiers"]):
            raise RuntimeError("Dynamic R1 fixture missed coverage/priority: " + number)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
