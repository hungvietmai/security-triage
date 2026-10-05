"""Development-only CodeQL guard evidence diagnostic; never suppresses alerts.

Reuses an existing paired-scan database and the shared process/version helpers.
The fixture database is static-only. Unknown evidence is not a negative label.
"""

import argparse
import json
from pathlib import Path
import shutil

from app.scanners.process import invoke, tool_version\nfrom experiments.run_pilot import ROOT, digest, write_json

QUERY = ROOT / "rules/codeql/python-evidence/ConstantIntegerGuard.ql"
FIXTURES = ROOT / "experiments/fixtures/constant-guard"
EXPECTATIONS = ROOT / "experiments/labels/owasp-python-cwe78-expectations.json"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def decode_rows(path):
    result = json.loads(path.read_text())["#select"]
    names = [c["name"] for c in result["columns"]]
    return [dict(zip(names, values, strict=True)) for values in result["tuples"]]


def check_fixtures(rows, expectations):
    expected = {}
    for case in expectations["cases"]:
        value = case["expected_evidence"]
        if value is not None:
            left, operator, right, outcome = value
            expected[(case["function"], case["guard_line"])] = [
                left, operator, right, outcome, "then" if outcome else "else"]
    actual = {}
    for row in rows:
        require(row["file"] == "cases.py", "Unexpected fixture source")
        key = (row["function_name"], row["guard_line"])
        require(key not in actual, "Duplicate/ambiguous fixture evidence")
        actual[key] = [row[k] for k in ["left_value", "comparison_operator",
                                      "right_value", "condition_value", "selected_branch"]]
    require(actual == expected, "Fixture evidence differs from prewritten expectations")
    return {"cases": len(expectations["cases"]), "matched_guard_records": len(actual),
            "expected_abstentions": len(expectations["cases"]) - len(actual),
            "status": "passed", "sink_safety_asserted": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark-run", type=Path, required=True)
    parser.add_argument("--codeql", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    base, binary, output = args.benchmark_run.resolve(), args.codeql.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {"status": "running", "split": "development", "steps": {},
              "suppression_authorized": False, "policy_decisions": [],
              "meaning": "Only a constant guard outcome when evaluated; not a proof of safe sink."}

    def run(name, command):
        step = invoke(list(map(str, command)), ROOT, output, name, 600)
        report["steps"][name] = step
        require(step["status"] == "completed", name + " failed; inspect retained logs")

    try:
        original = json.loads((base / "run.json").read_text())
        require(original["status"] == "completed", "Paired benchmark run must be complete")
        for filename, field in [("case.json", "case_manifest_sha256"),
                                ("config.json", "configuration_sha256"),
                                ("source.tgz", "snapshot_sha256")]:
            require(digest(base / filename) == original[field], "Base provenance mismatch: " + filename)
        case = json.loads((base / "case.json").read_text())
        target_labels = json.loads(EXPECTATIONS.read_text())
        require(case["source_commit"] == target_labels["source_commit"], "Benchmark source mismatch")
        report["base_run_sha256"] = digest(base / "run.json")
        report["base_source_sha256"] = original["snapshot_sha256"]
        report["base_configuration_commit"] = original["configuration_commit"]
        report["benchmark_database_source_zip_sha256"] = digest(base / "codeql-db/src.zip")
        pack_root = binary.parent / "qlpacks"
        manifest = pack_root / "codeql/python-all/7.2.6/qlpack.yml"
        report["python_library_manifest_sha256"] = digest(manifest)
        report["retained_input_sha256"] = {}
        for path in [QUERY, QUERY.parent / "qlpack.yml", FIXTURES / "cases.py",
                     FIXTURES / "expectations.json", EXPECTATIONS, Path(__file__)]:
            name = "target-expectations.json" if path == EXPECTATIONS else path.name
            shutil.copyfile(path, output / name)
            report["retained_input_sha256"][name] = digest(output / name)
        shutil.copyfile(base / "run.json", output / "base-run.json")
        tool_version(\n            str(binary),\n            "2.27.1",\n            output,\n            "codeql",\n            report["steps"],\n            working_directory=ROOT,\n            invoke_fn=invoke,\n        )
        fixture_db = output / "fixture-db"
        run("fixture-create", [binary, "database", "create", fixture_db,
                               "--language=python", "--source-root", FIXTURES,
                               "--build-mode=none", "--threads=1", "--ram=2048"])
        for name, database in [("benchmark", base / "codeql-db"), ("fixture", fixture_db)]:
            run(name + "-query", [binary, "query", "run", QUERY, "--database", database,
                                  "--search-path", pack_root, "--output", output / (name + ".bqrs"),
                                  "--threads=1", "--ram=2048", "--warnings=error"])
            run(name + "-decode", [binary, "bqrs", "decode", output / (name + ".bqrs"),
                                   "--format=json", "--output", output / (name + "-results.json")])
        expectations = json.loads((output / "expectations.json").read_text())
        report["fixture_checks"] = check_fixtures(decode_rows(output / "fixture-results.json"), expectations)
        all_rows = decode_rows(output / "benchmark-results.json")
        targets = {r["path"] for r in target_labels["cases"]}
        report["benchmark_guard_records"] = len(all_rows)
        report["target_guard_evidence"] = [r for r in all_rows if r["file"] in targets]
        report["other_guard_records_retained"] = len(all_rows) - len(report["target_guard_evidence"])
        report["status"] = "completed"
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        report["status"], report["error"] = "failed", str(exc)
    report["retained_output_sha256"] = {
        p.name: digest(p) for p in sorted(output.iterdir()) if p.is_file()}
    write_json(output / "run.json", report)
    print(json.dumps({k: v for k, v in report.items()
                      if k in {"status", "error", "fixture_checks", "target_guard_evidence"}}, indent=2))
    return 0 if report["status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
