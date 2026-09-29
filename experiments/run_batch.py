"""Run a fixed development manifest sequentially using the existing pilot CLI."""

import argparse
import csv
import json
import subprocess
import sys
from pathlib import Path

from experiments.run_pilot import ROOT, digest, write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", type=Path, required=True)
    parser.add_argument("--configuration-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--semgrep", required=True)
    parser.add_argument("--codeql", required=True)
    parser.add_argument("--javascript-query-pack", type=Path, required=True)
    parser.add_argument("--archive-directory", type=Path)
    args = parser.parse_args()
    batch = json.loads(args.batch.read_text())
    if batch["split"] != "development":
        parser.error("Held-out execution remains blocked")
    cases = [json.loads((ROOT / path).read_text()) for path in batch["case_manifests"]]
    ids = [case["case_id"] for case in cases]
    if len(ids) != len(set(ids)) or any(case["split"] != "development" for case in cases):
        parser.error("Cases must be distinct and development-only")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {
        "batch_id": batch["batch_id"],
        "batch_manifest_sha256": digest(args.batch),
        "configuration_commit": args.configuration_commit,
        "batch_runner_sha256": digest(Path(__file__)),
        "status": "running",
        "cases": [],
        "metrics": None,
    }
    write_json(output / "batch.json", batch)
    for case, manifest in zip(cases, batch["case_manifests"], strict=True):
        case_output = output / case["case_id"]
        argv = [
            sys.executable,
            str(ROOT / "experiments/run_pilot.py"),
            "--case",
            str(ROOT / manifest),
            "--config",
            str(ROOT / batch["config"]),
            "--configuration-commit",
            args.configuration_commit,
            "--output",
            str(case_output),
            "--semgrep",
            args.semgrep,
            "--codeql",
            args.codeql,
            "--javascript-query-pack",
            str(args.javascript_query_pack),
        ]
        if args.archive_directory:
            archive = (
                args.archive_directory / f"{case['package_name']}-{case['package_version']}.tgz"
            )
            argv.extend(["--source-archive", str(archive.resolve())])
        print(f"Starting {case['case_id']}", flush=True)
        with (output / f"{case['case_id']}.runner.log").open("w") as log:
            process = subprocess.run(argv, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        record = {"case_id": case["case_id"], "runner_exit_code": process.returncode}
        run_path = case_output / "run.json"
        if run_path.exists():
            run = json.loads(run_path.read_text())
            record.update(status=run["status"], snapshot_sha256=run.get("snapshot_sha256"))
            for tool in ("semgrep", "codeql"):
                step = run["steps"].get(tool, {})
                record[tool + "_status"] = step.get("status", "not_run")
                record[tool + "_raw_findings"] = step.get("raw_findings")
        else:
            record.update(status="runner_failed", error="No run.json; inspect runner log")
        report["cases"].append(record)
        write_json(output / "summary.json", report)
        print(json.dumps(record), flush=True)
    report["status"] = (
        "completed" if all(row["status"] == "completed" for row in report["cases"]) else "partial"
    )
    write_json(output / "summary.json", report)
    fields = [
        "case_id",
        "status",
        "runner_exit_code",
        "semgrep_status",
        "semgrep_raw_findings",
        "codeql_status",
        "codeql_raw_findings",
    ]
    with (output / "summary.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(report["cases"])
    return 0 if report["status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
