"""Join post-hoc paths to immutable Wave C endpoints; preserve raw outputs.

Run from the repository root after run_paths.py completes. A partially populated
bundle is intentional: query inputs, plan and check logs were saved before this
packaging step. Never overwrites packaged inputs or review cards.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import shutil
from datetime import datetime, timezone


def load(path):
    return json.loads(path.read_bytes())


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, data):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(data, indent=2, sort_keys=True) + "\n")


def location(physical):
    region = physical["region"]
    return (
        physical["artifactLocation"]["uri"],
        region["startLine"],
        region["startColumn"],
        region.get("endLine", region["startLine"]),
        region.get("endColumn"),
    )


def key(span):
    return f"{span[0]}:{span[1]}:{span[2]}"


def results(path):
    return [result for run in load(path)["runs"] for result in run.get("results", [])]


def endpoints(result):
    sink = location(result["locations"][0]["physicalLocation"])
    sources = {
        location(related["physicalLocation"])
        for related in result.get("relatedLocations", [])
        if related.get("message", {}).get("text") == "source"
    }
    if not sources:
        raise ValueError("Source message location missing")
    return {(source, sink) for source in sources}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True)
    args = parser.parse_args()
    root = Path.cwd().resolve()
    run_dir = (root / args.run).resolve()
    if not run_dir.is_relative_to(root / "artifacts/wave-c"):
        parser.error("Run must be under artifacts/wave-c")
    bundle = root / "experiments/wave-c/results/paths-001"
    primary = root / "experiments/wave-c/results/study-001"
    record = load(run_dir / "run.json")
    if record["status"] != "completed":
        raise ValueError("Diagnostic run did not complete")
    plan = load(bundle / "PLAN.json")
    for name, expected in plan["inputs"].items():
        if sha(root / name) != expected:
            raise ValueError(f"Pre-run input changed: {name}")
    for db in record["databases"].values():
        if db["original_before"] != db["original_after"] or not db["original_unchanged"]:
            raise ValueError("Original database preservation check failed")
    if sha(bundle / "pack/SafetyEvidence.qll") != sha(root / "artifacts/wave-c/toolchain/v02/SafetyEvidence.qll"):
        raise ValueError("SafetyEvidence import differs from baseline")
    if sha(bundle / "pack/codeql-pack.lock.yml") != sha(root / "experiments/wave-c/pack-locks/v02.lock.yml"):
        raise ValueError("Resolved dependency lock differs from baseline")

    ranks = {"dep0we/atomic-agents-stack": "03", "pipecat-ai/pipecat": "08"}
    paths_by_sink = {}
    edges_by_sink = {}
    comparisons = {}
    for rank in ("03", "08"):
        baseline = results(primary / "inputs" / rank / "none.sarif")
        path_results = results(run_dir / rank / "paths.sarif")
        before = set().union(*(endpoints(result) for result in baseline))
        after = set().union(*(endpoints(result) for result in path_results))
        if before != after:
            raise ValueError(f"Source/sink spans differ for {rank}: {before ^ after}")
        with (run_dir / rank / "edges.csv").open(encoding="utf-8", newline="") as stream:
            edges = list(csv.DictReader(stream))
        expected_keys = {(key(source), key(sink)) for source, sink in before}
        actual_keys = {(row["source_location"], row["sink_location"]) for row in edges}
        if expected_keys != actual_keys:
            raise ValueError(f"Edge endpoint pairs differ: {expected_keys ^ actual_keys}")
        for result in path_results:
            sink = location(result["locations"][0]["physicalLocation"])
            pair_set = endpoints(result)
            threads = [thread for flow in result.get("codeFlows", []) for thread in flow["threadFlows"]]
            if not threads:
                raise ValueError(f"No paths for {sink}")
            for thread in threads:
                steps = thread["locations"]
                pair = (location(steps[0]["location"]["physicalLocation"]), location(steps[-1]["location"]["physicalLocation"]))
                if pair not in pair_set:
                    raise ValueError("Path exemplar endpoints differ from alert endpoints")
            sink_key = (rank, key(sink))
            paths_by_sink[sink_key] = threads
            edges_by_sink[sink_key] = [row for row in edges if row["sink_location"] == key(sink)]
        comparisons[rank] = {
            "baseline_result_count": len(baseline),
            "path_result_count": len(path_results),
            "distinct_full_span_source_sink_pairs": len(before),
            "exact_pair_agreement_including_end_coordinates": True,
            "edge_endpoint_pair_agreement_start_coordinates": True,
            "sarif_thread_endpoint_agreement_full_span": True,
            "path_exemplar_count": sum(len(result["codeFlows"]) for result in path_results),
            "located_abstract_edge_rows": len(edges),
        }

    inputs = bundle / "inputs"
    inputs.mkdir(exist_ok=False)
    logs = bundle / "logs"
    logs.mkdir(exist_ok=False)
    units_dir = bundle / "units"
    units_dir.mkdir(exist_ok=False)
    for rank in ("03", "08"):
        (inputs / rank).mkdir()
        for name in ("paths.sarif", "edges.csv", "edges.json"):
            shutil.copyfile(run_dir / rank / name, inputs / rank / name)
    for path in sorted(run_dir.glob("*.log")):
        shutil.copyfile(path, logs / path.name)
    shutil.copyfile(run_dir / "run.json", bundle / "run.json")

    units = []
    for unit in load(primary / "evaluation/review_packet.json"):
        rank = ranks[unit["repository"]]
        sink_key = f"{unit['file']}:{unit['line']}:{unit['column']}"
        threads = paths_by_sink[(rank, sink_key)]
        edges = edges_by_sink[(rank, sink_key)]
        info = {
            "unit_id": unit["unit_id"],
            "repository": unit["repository"],
            "commit": unit["commit"],
            "sink_location": sink_key,
            "primary_trace_available": unit["trace_available"],
            "supplemental_trace_available": True,
            "path_exemplar_count": len(threads),
            "exemplar_step_counts": [len(thread["locations"]) for thread in threads],
            "located_abstract_edge_rows": len(edges),
            "callables_in_located_edges": sorted({row[field] for row in edges for field in ("from_callable", "to_callable")}),
            "sarif": f"inputs/{rank}/paths.sarif",
            "graph_csv": f"inputs/{rank}/edges.csv",
            "graph_json_with_entity_ids": f"inputs/{rank}/edges.json",
            "all_reported_flows_reviewed": False,
            "human_review_status": "pending",
        }
        units.append(info)
        lines = [f"# {unit['unit_id']}", "", f"Repository: `{unit['repository']}@{unit['commit']}`.", "",
                 f"Sink: `{sink_key}`. {len(threads)} path exemplars; {len(edges)} located abstract edge rows.", "",
                 "Post-hoc review aid. No label or suppression decision is included in this card.",
                 "Human review and `all_reported_flows_reviewed` remain pending/false.", "",
                 f"Raw [SARIF](../inputs/{rank}/paths.sarif), [edge CSV](../inputs/{rank}/edges.csv),",
                 f"[edge JSON](../inputs/{rank}/edges.json). Entity IDs in the JSON are local to this query result.", ""]
        for index, thread in enumerate(threads, 1):
            lines.extend([f"## Path exemplar {index}", "", "| Step | Source location | CodeQL node |", "|---:|---|---|"])
            for step_index, step in enumerate(thread["locations"], 1):
                loc = step["location"]
                span = location(loc["physicalLocation"])
                url = f"https://github.com/{unit['repository']}/blob/{unit['commit']}/{span[0]}#L{span[1]}"
                message = loc.get("message", {}).get("text", "").replace("|", "\\|").replace("\n", " ")
                lines.append(f"| {step_index} | [{key(span)}]({url}) | {message} |")
            lines.append("")
        lines.extend(["These are selected CodeQL paths, not an enumeration of executions. Located edges can", "include summarized calls or infeasible combinations; missing guard nodes do not prove", "the guard is absent. Read the source alongside each path before assigning a label.", ""])
        (units_dir / f"{unit['unit_id']}.md").write_text("\n".join(lines), encoding="utf-8", newline="\n")

    if len(units) != 8 or len(paths_by_sink) != 8:
        raise ValueError("Expected exactly eight joined sink units")
    summary = {
        "classification": record["classification"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "comparisons": comparisons,
        "units": units,
        "total_units": len(units),
        "total_path_exemplars": sum(unit["path_exemplar_count"] for unit in units),
        "total_located_abstract_edge_rows": sum(unit["located_abstract_edge_rows"] for unit in units),
        "diagnostic_command_wall_seconds": sum(command["wall_seconds"] for command in record["commands"]),
        "human_review_seconds": 0,
        "label_changes": 0,
        "primary_results_lock_sha256": sha(primary / "RESULTS_LOCK.sha256"),
        "prior_review_lock_sha256": sha(root / "experiments/wave-c/results/review-001/REVIEW_LOCK.sha256"),
        "limitation": "Reported exemplars and located abstract edges are not exhaustive concrete executions or proof of safety; no human label promotion.",
    }
    save(bundle / "summary.json", summary)
    print(json.dumps({key: value for key, value in summary.items() if key not in ("units", "comparisons")}, indent=2))


if __name__ == "__main__":
    main()
