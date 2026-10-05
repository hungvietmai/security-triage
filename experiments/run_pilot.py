"""Development-only, manifest-driven static scan runner (Python 3.12+).

The CLI owns only argument parsing, freeze gates, artifact writing and delegation
to the reusable scanner package. No benchmark code/install hooks are executed.
"""

import argparse
import csv
import json
import re
import tarfile
import time
from pathlib import Path

from app.scanners.acquisition import (
    MAX_ARCHIVE,
    MAX_FILES,
    MAX_UNPACKED,
    AcquisitionLimits,
    acquire_source,
)
from app.scanners.pipeline import run_pipeline
from app.scanners.provenance import digest

ROOT = Path(__file__).resolve().parents[1]
SCANNER_ROOT = ROOT / "backend/app/scanners"


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def runner_files_sha256():
    """Hash the thin CLI plus every Python file that implements scanner logic."""
    files = [Path(__file__).resolve(), *sorted(SCANNER_ROOT.glob("*.py"))]
    return {str(path.relative_to(ROOT)): digest(path) for path in files}


def _write_findings_csv(path, findings):
    fields = [
        "raw_id",
        "tool",
        "rule_id",
        "reported_path",
        "reported_region",
        "mapping_status",
        "message",
    ]
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(findings)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--configuration-commit", required=True)
    parser.add_argument("--semgrep", default="semgrep")
    parser.add_argument("--codeql", default="codeql")
    parser.add_argument("--javascript-query-pack", type=Path)
    parser.add_argument("--python-query-pack", type=Path)
    parser.add_argument(
        "--source-archive", type=Path, help="Reuse an archive with the manifest hash"
    )
    args = parser.parse_args()

    if not re.fullmatch(r"[a-f0-9]{40}", args.configuration_commit):
        parser.error("Exact configuration commit required")

    case_bytes = args.case.read_bytes()
    config_bytes = args.config.read_bytes()
    case = json.loads(case_bytes)
    config = json.loads(config_bytes)

    if case["split"] != "development":
        parser.error(
            "Held-out execution is blocked: full freeze gate is not implemented"
        )
    if (case["source_kind"], case["language"]) not in {
        ("npm_tarball", "javascript"),
        ("github_tarball", "javascript"),
        ("github_tarball", "python"),
    }:
        parser.error(
            "Supported sources: JavaScript npm, or pinned GitHub JS/Python archives"
        )
    if config.get("language", "javascript") != case["language"]:
        parser.error("Case and scanner configuration languages must agree")
    if set(config["scanners"]) - {"semgrep", "codeql"}:
        parser.error("Unsupported scanner; ST/S1 are not implemented yet")

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / "case.json").write_bytes(case_bytes)
    (output / "config.json").write_bytes(config_bytes)

    protocol_path = ROOT / "experiments/EVALUATION_PROTOCOL.md"
    report = {
        "case_id": case["case_id"],
        "split": case["split"],
        "config_id": config["config_id"],
        "purpose": config["purpose"],
        "protocol_commit": config["protocol_commit"],
        "configuration_commit": args.configuration_commit,
        "protocol_sha256": digest(protocol_path),
        "case_manifest_sha256": digest(output / "case.json"),
        "configuration_sha256": digest(output / "config.json"),
        "runner_files_sha256": runner_files_sha256(),
        "status": "running",
        "steps": {},
        "labels_commit": None,
        "mapping_version": "raw-ledger-v0",
        "metrics": None,
        "metrics_reason": "No reviewed common location/label ledger yet",
    }

    findings = []
    start = time.monotonic()
    try:
        acquired = acquire_source(
            case,
            output,
            source_archive=args.source_archive,
            limits=AcquisitionLimits(
                max_archive_bytes=MAX_ARCHIVE,
                max_unpacked_bytes=MAX_UNPACKED,
                max_files=MAX_FILES,
            ),
        )
        report["snapshot_sha256"] = acquired.snapshot_sha256
        report["source_files"] = acquired.source_files
        report["steps"]["acquisition"] = {
            "status": "completed",
            "transport": acquired.transport,
            "seconds": acquired.seconds,
        }

        result = run_pipeline(
            scanners=config["scanners"],
            language=case["language"],
            source=acquired.source_path,
            output=output,
            snapshot_sha256=acquired.snapshot_sha256,
            repository_root=ROOT,
            semgrep_binary=args.semgrep,
            codeql_binary=args.codeql,
            semgrep_version=config["semgrep_version"],
            codeql_version=config["codeql_version"],
            semgrep_rules=config["semgrep_rules"],
            codeql_queries=config["codeql_queries"],
            codeql_query_sha256=config["codeql_query_sha256"],
            javascript_query_pack=args.javascript_query_pack,
            python_query_pack=args.python_query_pack,
            jobs=config["jobs"],
            timeout_seconds=config["timeout_seconds"],
            codeql_ram_mb=2048,
        )
        report["steps"].update(result.steps)
        report["status"] = result.status
        findings.extend(result.findings)
        if result.codeql_query_files is not None:
            report["codeql_query_files"] = result.codeql_query_files
        if result.codeql_pack_manifest is not None:
            report["codeql_pack_manifest"] = result.codeql_pack_manifest
    except (OSError, ValueError, RuntimeError, KeyError, tarfile.TarError) as exc:
        report["status"] = "failed"
        report["error"] = str(exc)

    report["wall_seconds"] = round(time.monotonic() - start, 4)
    report["raw_findings"] = len(findings)
    write_json(output / "findings.json", findings)
    _write_findings_csv(output / "findings.csv", findings)
    write_json(output / "run.json", report)
    print(
        json.dumps(
            {
                "status": report["status"],
                "raw_findings": len(findings),
                "output": str(output),
            }
        )
    )
    return 0 if report["status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
