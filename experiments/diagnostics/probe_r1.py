"""Scan fixed synthetic R1 probes with the same pinned rules and common scanner helpers."""

import argparse
import json
from pathlib import Path

from experiments.run_pilot import (
    ROOT,
    digest,
    invoke,
    sarif_findings,
    stage_rule,
    tool_version,
    write_json,
)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--semgrep", required=True)
    p.add_argument("--codeql", required=True)
    p.add_argument("--javascript-query-pack", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    source = ROOT / "experiments/fixtures/r1-feasibility"
    manifest = json.loads((source / "manifest.json").read_text())
    for case in manifest["cases"]:
        if digest(source / case["file"]) != case["source_sha256"]:
            raise ValueError("Fixture digest mismatch")
    for name, expected in manifest["support_files"].items():
        if digest(source / name) != expected:
            raise ValueError("Support file digest mismatch")
    config_path = ROOT / "experiments/configs/development-batch-01-upstream.json"
    config = json.loads(config_path.read_text())
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    write_json(out / "config.json", config)
    write_json(out / "manifest.json", manifest)
    report = {
        "kind": manifest["kind"],
        "runner_sha256": digest(Path(__file__)),
        "manifest_sha256": digest(source / "manifest.json"),
        "config_sha256": digest(config_path),
        "steps": {},
        "metrics": None,
    }
    findings = []
    for tool, binary in [("semgrep", args.semgrep), ("codeql", args.codeql)]:
        try:
            tool_version(binary, config[tool + "_version"], out, tool, report["steps"])
            sarif = out / (tool + ".sarif")
            if tool == "semgrep":
                argv = [
                    binary,
                    "scan",
                    "--metrics=off",
                    "--disable-version-check",
                    "--disable-nosem",
                    "--no-git-ignore",
                    "--jobs",
                    str(config["jobs"]),
                    "--sarif",
                    "--output",
                    str(sarif),
                ]
                for i, spec in enumerate(config["semgrep_rules"]):
                    rule = out / f"rule-{i}.yaml"
                    stage_rule(spec, rule)
                    argv += ["--config", str(rule)]
                argv += ["."]
            else:
                pack = args.javascript_query_pack.resolve()
                queries = [pack / n for n in config["codeql_queries"]]
                for q in queries:
                    if (
                        digest(q)
                        != config["codeql_query_sha256"][str(q.relative_to(pack))]
                    ):
                        raise ValueError("Query digest mismatch")
                report["query_pack_manifest"] = (pack / "qlpack.yml").read_text()
                db = out / "codeql-db"
                create = invoke(
                    [
                        binary,
                        "database",
                        "create",
                        str(db),
                        "--language=javascript",
                        "--source-root",
                        str(source),
                        "--build-mode=none",
                        "--threads",
                        str(config["jobs"]),
                        "--ram=2048",
                    ],
                    source,
                    out,
                    "codeql-create",
                    config["timeout_seconds"],
                )
                report["steps"]["codeql-create"] = create
                if create["status"] != "completed":
                    raise RuntimeError("CodeQL extraction failed")
                argv = [
                    binary,
                    "database",
                    "analyze",
                    str(db),
                    *map(str, queries),
                    "--format=sarif-latest",
                    "--output",
                    str(sarif),
                    "--threads",
                    str(config["jobs"]),
                    "--ram=2048",
                ]
            step = invoke(argv, source, out, tool, config["timeout_seconds"])
            report["steps"][tool] = step
            if not sarif.exists():
                raise RuntimeError("No SARIF output")
            rows, complete = sarif_findings(sarif, tool, report["manifest_sha256"])
            findings += rows
            step["raw_findings"] = len(rows)
            step["sarif_sha256"] = digest(sarif)
            if step["status"] == "completed" and not complete:
                step["status"] = "partial"
        except (OSError, ValueError, RuntimeError, KeyError) as exc:
            step = report["steps"].setdefault(tool, {})
            step["status"] = "timeout" if step.get("status") == "timeout" else "failed"
            step["error"] = str(exc)
    report["status"] = (
        "completed"
        if all(
            report["steps"][t]["status"] == "completed" for t in ("semgrep", "codeql")
        )
        else "partial"
    )
    write_json(out / "findings.json", findings)
    write_json(out / "run.json", report)
    print(json.dumps({"status": report["status"], "raw_findings": len(findings)}))
    return 0 if report["status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
