"""Audit saved review evidence and downloaded source without executing target code.

Run from the repository root; source files stay in ignored artifacts/. This is
an evidence integrity check, not an oracle for labels or human review status.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlsplit


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def location(physical: dict) -> tuple[str, int, int]:
    region = physical["region"]
    return (
        physical["artifactLocation"]["uri"],
        region["startLine"],
        region["startColumn"],
    )


def subsequence(shorter: list, longer: list) -> bool:
    remaining = iter(longer)
    return all(any(candidate == item for candidate in remaining) for item in shorter)


def relative(entity: dict, archive_root: str) -> tuple[str, int, int]:
    url = entity["url"]
    suffix = unquote(urlsplit(url["uri"]).path).split(
        "/extracted/" + archive_root + "/", 1
    )[1]
    return suffix, url["startLine"], url["startColumn"]


def finite_routes(adjacency: dict, start: int, end: int) -> list:
    paths = []

    def walk(current, history):
        if current in history:
            raise ValueError("Cyclic graph: finite-route claim not supported")
        history = history + [current]
        if current == end:
            paths.append(history)
            return
        for successor in sorted(adjacency[current]):
            walk(successor, history)

    walk(start, [])
    return paths


def audit(source_manifest: Path) -> dict:
    manifest = load(source_manifest)
    files = {}
    for row in manifest["files"]:
        if row["status"] != "downloaded":
            continue
        path = Path(row["local_path"])
        if digest(path) != row["sha256"]:
            raise ValueError(f"Downloaded source hash mismatch: {path}")
        files[row["repository"], row["commit"], row["file"]] = row

    old_audit = load(Path("experiments/wave-c/results/review-001/source_audit.json"))
    expected = {
        (repo["repository"], file["file"]): file["sha256"]
        for repo in old_audit["audited_repositories"]
        for file in repo["files"]
    }
    queue_path = Path("experiments/wave-c/closeout/owner-review/review_queue.csv")
    with queue_path.open(encoding="utf-8", newline="") as stream:
        queue = list(csv.DictReader(stream))
    identities = {
        (r["repository"], r["file"], int(r["line"]), int(r["column"])): r["unit_id"]
        for r in queue
    }
    records = load(Path("experiments/wave-c/sources.lock.json"))["records"]
    units, nodes_checked, summaries = [], 0, 0
    for rank in ("03", "08"):
        record = next(r for r in records if r["rank"] == int(rank))
        repo = record["repository"]
        graph = load(
            Path(f"experiments/wave-c/closeout/self-review/decoded/{rank}-paths.json")
        )
        sarif = load(
            Path(f"experiments/wave-c/results/paths-001/inputs/{rank}/paths.sarif")
        )

        nodes = {r[0]["id"]: r[0] for r in graph["nodes"]["tuples"]}
        by_span = {}
        for identity, entity in nodes.items():
            key = relative(entity, record["archive_root"])
            if key in by_span:
                raise ValueError("Ambiguous graph coordinates")
            by_span[key] = identity
            source = next(
                r
                for (project, _, file), r in files.items()
                if project == repo and file == key[0]
            )
            if source["sha256"] != expected[repo, key[0]]:
                raise ValueError("Source differs from historical locked-archive audit")
            lines = Path(source["local_path"]).read_text(encoding="utf-8").splitlines()
            url = entity["url"]
            if not (
                1 <= key[1] <= url["endLine"] <= len(lines)
                and 1 <= key[2]
                and url["endColumn"] <= len(lines[url["endLine"] - 1])
            ):
                raise ValueError("Invalid graph source span")
        nodes_checked += len(nodes)
        adjacency = {key: set() for key in nodes}
        for left, right, _, _ in graph["edges"]["tuples"]:
            adjacency[left["id"]].add(right["id"])
        summaries += len(graph["subpaths"]["tuples"])
        alerts = {
            location(r["locations"][0]["physicalLocation"]): r
            for run in sarif["runs"]
            for r in run["results"]
        }
        for row in graph["#select"]["tuples"]:
            start, end = row[1], row[2]
            key = relative(end, record["archive_root"])
            paths = finite_routes(adjacency, start["id"], end["id"])
            examples = [
                [
                    by_span[location(step["location"]["physicalLocation"])]
                    for step in thread["locations"]
                ]
                for flow in alerts[key]["codeFlows"]
                for thread in flow["threadFlows"]
            ]
            if (
                not paths
                or len(paths) != len(examples)
                or not all(
                    sum(subsequence(path, example) for example in examples) == 1
                    for path in paths
                )
                or not all(
                    sum(subsequence(path, example) for path in paths) == 1
                    for example in examples
                )
            ):
                raise ValueError("Abstract routes and expanded exemplars differ")
            units.append(
                {
                    "unit_id": identities[repo, *key],
                    "sink": list(key),
                    "abstract_route_count": len(paths),
                    "exemplar_count": len(examples),
                    "source_matches_historical_audit": True,
                }
            )
    if len(units) != 8 or sum(u["exemplar_count"] for u in units) != 18:
        raise ValueError("Unexpected Wave C review population")

    b_path = Path("experiments/wave-b/results/wave_b_labels.csv")
    with b_path.open(encoding="utf-8", newline="") as stream:
        pending = [
            r
            for r in csv.DictReader(stream)
            if "owner_review_pending" in r["review_status"]
        ]
    if len(pending) != 17:
        raise ValueError("Unexpected Wave B pending population")
    for row in pending:
        file, line, column = row["sink_location"].rsplit(":", 2)
        matches = [
            r
            for (repo, _, name), r in files.items()
            if repo == row["repository"] and name == file
        ]
        if len(matches) != 2 or len({r["sha256"] for r in matches}) != 1:
            raise ValueError("Wave B sink file must match both locked snapshots")
        lines = Path(matches[0]["local_path"]).read_text(encoding="utf-8").splitlines()
        if not (
            1 <= int(line) <= len(lines)
            and 1 <= int(column) <= len(lines[int(line) - 1])
        ):
            raise ValueError("Invalid Wave B sink span")

    return {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_manifest_sha256": digest(source_manifest),
        "downloaded_files_verified": len(files),
        "failed_source_requests": [
            r for r in manifest["files"] if r["status"] != "downloaded"
        ],
        "wave_c": {
            "units": units,
            "graph_nodes_verified": nodes_checked,
            "summary_rows": summaries,
            "claim_scope": "saved finite abstract graph only",
        },
        "wave_b": {
            "pending_alerts": len(pending),
            "root_cause_counts": dict(Counter(r["root_cause_id"] for r in pending)),
            "sink_files_equal_between_snapshots": True,
            "original_codeql_paths_available": False,
            "all_reported_flows_reviewed": False,
        },
        "human_review_confirmed": False,
        "scanner_runs": 0,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = audit(args.sources)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(
        "Verified 8 Wave C sinks / 18 exemplars and 17 Wave B sink locations; no scanners run."
    )
