"""Scan a case's npm package through the API and require the CLI's exact result.

The worker acquires the package by its name and version through the npm integrity path;
the CLI used the case's pinned hash. Both must see the same bytes (snapshot SHA-256 equals
the case's artifact_sha256), and from them the same units, priorities and raw findings.

    python experiments/diagnostics/scan_parity.py --api http://localhost:8000 \
        --case experiments/cases/secbench-curling-0.2.0.json --cli-run artifacts/cli \
        --output artifacts/parity.json [--expect-tier P1=1]
"""

import argparse
import json
import sys
import time
import urllib.request
from collections import Counter
from pathlib import Path


def call(api, method, path, body=None):
    request = urllib.request.Request(
        api.rstrip("/") + "/api/v1" + path,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method=method,
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read())


def scan_through_api(api, case, timeout_seconds):
    project = call(api, "POST", "/projects", {"name": f"parity {case['case_id']}"})
    source = {"kind": "npm", "package": case["package_name"], "version": case["package_version"]}
    accepted = call(api, "POST", f"/projects/{project['id']}/scans", {"source": source})
    deadline = time.monotonic() + timeout_seconds
    while True:
        scan = call(api, "GET", f"/scans/{accepted['scan_id']}")
        if scan["status"] not in {"queued", "running"}:
            break
        if time.monotonic() > deadline:
            raise TimeoutError(f"Scan still {scan['status']} after {timeout_seconds} s")
        time.sleep(5)
    units, offset = [], 0
    while True:
        page = call(api, "GET", f"/scans/{scan['id']}/units?limit=100&offset={offset}")
        units += page["items"]
        offset += page["limit"]
        if offset >= page["total"]:
            break
    details = [call(api, "GET", f"/scans/{scan['id']}/units/{unit['id']}") for unit in units]
    return scan, details


def compare(case, scan, details, cli_run):
    run = json.loads((cli_run / "run.json").read_text(encoding="utf-8"))
    cli_units = json.loads((cli_run / "units.json").read_text(encoding="utf-8"))
    cli_assessments = json.loads((cli_run / "assessments.json").read_text(encoding="utf-8"))
    api_findings = Counter(f["tool"] for d in details for f in d["findings"])
    cli_findings = {
        tool: run["steps"][tool]["raw_findings"] for tool in ("semgrep", "codeql") if tool in run["steps"]
    }
    checks = {
        "scan_completed": scan["status"] == "completed",
        "snapshot_is_the_pinned_archive": scan["snapshot"]["sha256"] == case["artifact_sha256"],
        "snapshot_publisher_verified": scan["snapshot"]["provenance_kind"] == "publisher_verified",
        "cli_config_is_profile_config": run["config_id"] == "development-batch-01-upstream",
        "same_unit_ids": sorted(d["unit_key"] for d in details)
        == sorted(u["unit_id"] for u in cli_units),
        "same_priorities": {d["unit_key"]: d["priority"] for d in details}
        == {a["unit_id"]: a["priority"] for a in cli_assessments},
        "same_raw_findings_per_tool": {tool: api_findings.get(tool, 0) for tool in cli_findings}
        == cli_findings,
        "same_raw_findings_per_unit": {d["unit_key"]: len(d["findings"]) for d in details}
        == {u["unit_id"]: len(u["raw_finding_ids"]) for u in cli_units},
        "same_policy_hash": {d["policy_sha256"] for d in details}
        == {a["policy_sha256"] for a in cli_assessments},
    }
    report = {
        "case_id": case["case_id"],
        "scan_id": scan["id"],
        "snapshot_sha256": scan["snapshot"]["sha256"],
        "api_units": {d["unit_key"]: d["priority"] for d in details},
        "api_raw_findings": dict(api_findings),
        "cli_raw_findings": cli_findings,
        "unit_counts": scan["unit_counts"],
        "checks": checks,
    }
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api", required=True)
    parser.add_argument("--case", type=Path, required=True)
    parser.add_argument("--cli-run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--expect-tier", action="append", default=[], help="e.g. P1=1")
    args = parser.parse_args(argv)
    case = json.loads(args.case.read_text(encoding="utf-8"))
    scan, details = scan_through_api(args.api, case, args.timeout)
    report = compare(case, scan, details, args.cli_run)
    for expectation in args.expect_tier:
        tier, count = expectation.split("=")
        report["checks"][f"expected_{tier}_units"] = scan["unit_counts"][tier] == int(count)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    failed = [name for name, ok in report["checks"].items() if not ok]
    if failed:
        print("PARITY FAILED:", ", ".join(failed), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
