"""Audit saved graphs/paths against pinned source; no scanner or label inference.

Run from repository root. Writes a fresh audit.json and nodes.csv.
"""

import csv
import hashlib
import json
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit
from datetime import datetime, timezone


def load(path):
    return json.loads(path.read_bytes())


def stripped(value):
    if isinstance(value, dict):
        if "id" in value and "label" in value:
            return {"label": value["label"]}
        return {key: stripped(item) for key, item in value.items()}
    if isinstance(value, list):
        return [stripped(item) for item in value]
    return value


def span(location):
    region = location["region"]
    return (location["artifactLocation"]["uri"], region["startLine"], region["startColumn"])


def subsequence(shorter, longer):
    remaining = iter(longer)
    return all(any(value == wanted for value in remaining) for wanted in shorter)


def main():
    root = Path.cwd()
    output = root / "experiments/wave-c/closeout/self-review"
    sources = load(root / "experiments/wave-c/sources.lock.json")["records"]
    prior_audit = load(root / "experiments/wave-c/results/review-001/source_audit.json")
    expected_hashes = {(repo["repository"], file["file"]): file["sha256"]
                       for repo in prior_audit["audited_repositories"] for file in repo["files"]}
    packet = load(root / "experiments/wave-c/results/study-001/evaluation/review_packet.json")
    unit_ids = {(row["repository"], row["file"], row["line"], row["column"]): row["unit_id"] for row in packet}
    units, node_rows, rank_reports = [], [], []
    for rank in ("03", "08"):
        source = next(row for row in sources if row["rank"] == int(rank))
        prefix = "/extracted/" + source["archive_root"] + "/"

        def relative(entity):
            url = entity["url"]
            relative_name = unquote(urlsplit(url["uri"]).path).split(prefix, 1)[1]
            parts = PurePosixPath(relative_name)
            if parts.is_absolute() or ".." in parts.parts:
                raise ValueError("Unsafe graph source path")
            return (relative_name, url["startLine"], url["startColumn"])

        edge_graph = load(output / "decoded" / f"{rank}-edges.json")
        old_graph = load(root / f"experiments/wave-c/results/paths-001/inputs/{rank}/edges.json")
        assert stripped(edge_graph) == old_graph, "Decoding changed more than entity representation"
        graph = load(output / "decoded" / f"{rank}-paths.json")
        assert all(stripped(graph[key]) == old_graph[key] for key in ("edges", "nodes", "subpaths"))
        nodes = {row[0]["id"]: row[0] for row in graph["nodes"]["tuples"]}
        by_span = {}
        for identity, entity in nodes.items():
            key = relative(entity)
            assert key not in by_span, "Multiple graph nodes at same coordinates require state-aware matching"
            by_span[key] = identity
            path = root / f"artifacts/wave-c/study-001/{rank}/extracted" / source["archive_root"] / key[0]
            actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            assert actual_hash == expected_hashes[(source["repository"], key[0])]
            lines = path.read_text(encoding="utf-8").splitlines()
            url = entity["url"]
            assert 1 <= key[1] <= url["endLine"] <= len(lines)
            assert key[2] >= 1 and url["endColumn"] <= len(lines[url["endLine"] - 1])
            node_rows.append({"rank": rank, "entity_id": identity, "file": key[0],
                              "line": key[1], "column": key[2], "label": entity["label"],
                              "source_line": lines[key[1] - 1], "source_sha256": actual_hash})
        adjacency = {identity: set() for identity in nodes}
        for left, right, _, _ in graph["edges"]["tuples"]:
            assert left["id"] in nodes and right["id"] in nodes
            adjacency[left["id"]].add(right["id"])
        for summary in graph["subpaths"]["tuples"]:
            assert all(item["id"] in nodes for item in summary)
        sarif = load(root / f"experiments/wave-c/results/paths-001/inputs/{rank}/paths.sarif")
        alerts = {span(result["locations"][0]["physicalLocation"]): result for run in sarif["runs"] for result in run["results"]}
        for row in graph["#select"]["tuples"]:
            source_node, sink_node = row[1], row[2]
            sink_key = relative(sink_node)
            result = alerts[sink_key]
            assert relative(row[0]) == sink_key
            assert relative(row[4]) == relative(source_node)
            found_paths = []

            def walk(current, history):
                if current in history:
                    raise ValueError("Cycle encountered; do not claim exhaustive finite route coverage")
                history = history + [current]
                if current == sink_node["id"]:
                    found_paths.append(history)
                    return
                for successor in sorted(adjacency[current]):
                    walk(successor, history)

            walk(source_node["id"], [])
            exemplars = []
            for flow in result["codeFlows"]:
                for thread in flow["threadFlows"]:
                    steps = [span(item["location"]["physicalLocation"]) for item in thread["locations"]]
                    assert steps[0] == relative(source_node) and steps[-1] == sink_key
                    exemplars.append([by_span[key] for key in steps])
            assert found_paths and len(found_paths) == len(exemplars)
            assert all(sum(subsequence(path, example) for example in exemplars) == 1 for path in found_paths)
            assert all(sum(subsequence(path, example) for path in found_paths) == 1 for example in exemplars)
            units.append({
                "unit_id": unit_ids[(source["repository"], *sink_key)],
                "repository": source["repository"], "sink": list(sink_key),
                "abstract_routes": found_paths, "sarif_expanded_exemplars": exemplars,
                "every_finite_abstract_route_matched_one_exemplar": True,
                "claim_scope": "saved finite abstract graph and exported summary edges; not all concrete executions",
            })
        label_counts = {}
        for entity in nodes.values():
            label_counts.setdefault(entity["label"], []).append(entity["id"])
        rank_reports.append({"rank": rank, "graph_nodes": len(nodes),
                             "graph_edge_rows": len(graph["edges"]["tuples"]),
                             "summary_rows": len(graph["subpaths"]["tuples"]),
                             "selected_edge_rows": len(edge_graph["#select"]["tuples"]),
                             "duplicate_labels": {name: ids for name, ids in label_counts.items() if len(ids) > 1},
                             "label_only_decode_preserved": True})
    assert len(units) == 8 and sum(len(unit["sarif_expanded_exemplars"]) for unit in units) == 18
    with (output / "nodes.csv").open("x", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(node_rows[0]))
        writer.writeheader()
        writer.writerows(node_rows)
    with (output / "audit.json").open("x", encoding="utf-8") as stream:
        json.dump({"created_at": datetime.now(timezone.utc).isoformat(),
                   "classification": "same exposed assistant, post-hoc technical review aid",
                   "ranks": rank_reports, "units": units,
                   "graph_nodes_checked_against_pinned_source": len(node_rows),
                   "human_review_confirmed": False, "query_runs": 0}, stream, indent=2)
        stream.write("\n")
    print(f"Audited {len(units)} sinks, 18 exemplars, {len(node_rows)} distinct per-repository graph nodes and 3 summary rows; IDs retained.")


if __name__ == "__main__":
    main()
