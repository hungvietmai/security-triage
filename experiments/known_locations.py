"""Resolve dataset locations on locked development snapshots without running scanners."""

# Direct CLI execution bootstraps the repository/backend before shared imports.
# ruff: noqa: E402

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from experiments.lock_pair_sources import CACHE
from experiments.make_pair_manifests import PAIRS, sha256, write_json
from experiments.patch_hunks import load_pair

from app.triage.sinks_python import locate_python_sinks

JS_LOCATOR = ROOT / "experiments/locators/pair-javascript-ast.cjs"
PYVUL_FUNCTIONS_URL = "https://raw.githubusercontent.com/billquan/PyVul/1172bfd1579b4ad2a524549412170d08ca618fb3/dataset/function_level_dataset.out"
PYVUL_FUNCTIONS_SHA256 = "73eb0e3cce41721345d3acca2169266db6888e46f9f33394dad3bed549711071"


def locate_javascript(path: str, source: str, *, node: str = "node"):
    result = subprocess.run(
        [node, str(JS_LOCATOR)],
        input=json.dumps({"path": path, "source": source}),
        text=True,
        encoding="utf-8",
        capture_output=True,
        timeout=30,
        check=False,
    )
    if result.returncode:
        raise ValueError(f"JavaScript AST locator failed: {result.stderr[:1000]}")
    return json.loads(result.stdout)


def resolve_secbench(manifest, files, *, node="node", locator_fn=locate_javascript):
    provenance = {
        "kind": "SecBench.js_sink_hint",
        "hint": manifest.get("sink_hint"),
        "references": manifest["reference_provenance"],
        "inventory_basis": manifest["os_command_execution_basis"],
        "locator": "pair-javascript-ast-v0",
        "locator_sha256": sha256(JS_LOCATOR),
    }
    if not manifest.get("sink_hint"):
        return (
            [],
            [
                {
                    "status": "known_location_unresolved",
                    "reason": "sink_hint_missing",
                    "provenance": provenance,
                }
            ],
            {},
        )
    path, line, column = manifest["sink_hint"].rsplit(":", 2)
    if path not in files:
        return (
            [],
            [
                {
                    "status": "known_location_unresolved",
                    "reason": "sink_hint_file_missing",
                    "provenance": provenance,
                }
            ],
            {},
        )
    try:
        output = locator_fn(path, files[path].decode("utf-8"), node=node)
    except (ValueError, UnicodeError, OSError, subprocess.TimeoutExpired) as error:
        return (
            [],
            [
                {
                    "status": "known_location_unresolved",
                    "reason": str(error),
                    "provenance": provenance,
                }
            ],
            {},
        )
    point = int(line), int(column)
    matches = [
        sink
        for sink in output["sinks"]
        if (sink["callee_span"]["startLine"], sink["callee_span"]["startColumn"])
        <= point
        < (sink["callee_span"]["endLine"], sink["callee_span"]["endColumn"])
    ]
    if len(matches) != 1:
        return (
            [],
            [
                {
                    "status": "known_location_unresolved",
                    "reason": "sink_hint_not_uniquely_contained_in_callee",
                    "candidate_count": len(matches),
                    "provenance": provenance,
                }
            ],
            {
                "javascript_parser_version": output["parser_version"],
                "javascript_traverse_version": output["traverse_version"],
            },
        )
    location = {
        "status": "resolved",
        "path": path,
        "span": matches[0]["span"],
        "sink_kind": matches[0]["sink_kind"],
        "callee": matches[0]["callee"],
        "provenance": provenance,
    }
    return (
        [location],
        [],
        {
            "javascript_parser_version": output["parser_version"],
            "javascript_traverse_version": output["traverse_version"],
        },
    )


def function_labels(manifest, dataset_path: Path | None):
    if dataset_path is None:
        return [], {"status": "unavailable", "source": PYVUL_FUNCTIONS_URL}
    if sha256(dataset_path) != PYVUL_FUNCTIONS_SHA256:
        raise ValueError("PyVul function dataset checksum mismatch")
    expected_commit = f"https://github.com/{manifest['repository']}/commit/{manifest['fix_commit']}"
    records = []
    with dataset_path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            record = json.loads(line)
            if record["commit"].lower() != expected_commit.lower():
                continue
            # Use published changed-function metadata; do not infer labels from prose.
            records.append(
                {
                    "function_name": record["function_name"],
                    "normalized_code_before_sha256": hashlib.sha256(
                        textwrap.dedent(record["code_before"]).strip().encode()
                    ).hexdigest(),
                    "dataset_line": line_number,
                    "commit": record["commit"],
                }
            )
    return records, {
        "status": "available" if records else "no_matching_commit",
        "source": PYVUL_FUNCTIONS_URL,
        "sha256": PYVUL_FUNCTIONS_SHA256,
        "labels": records,
        "basis": "published changed-function records; not independent vulnerability adjudication",
    }


def resolve_pyvul(
    manifest, files, hunks, *, labels=None, label_provenance=None, locator_fn=locate_python_sinks
):
    locations, unresolved, outside_labels = [], [], []
    for file in hunks["files"]:
        path = file["old_path"]
        if not path or not path.endswith(".py"):
            continue
        changed_lines = {
            line
            for hunk in file["hunks"]
            for change in hunk["changes"]
            for line in change["old_lines"]
        }
        if not changed_lines:
            continue
        provenance = {
            "kind": "PyVul_deleted_or_modified_lines",
            "references": manifest["reference_provenance"],
            "fix_commit": manifest["fix_commit"],
            "patch_lines": sorted(changed_lines),
            "function_labels": label_provenance or {"status": "unavailable"},
            "locator": "app.triage.sinks_python.locate_python_sinks",
            "locator_sha256": sha256(ROOT / "backend/app/triage/sinks_python.py"),
        }
        try:
            source = files[path].decode("utf-8")
            sinks = locator_fn(path, source)
            functions = [
                node
                for node in ast.walk(ast.parse(source))
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
        except (SyntaxError, UnicodeError, ValueError) as error:
            unresolved.append(
                {
                    "status": "known_location_unresolved",
                    "path": path,
                    "reason": f"Python locator could not parse changed file: {error}",
                    "provenance": provenance,
                }
            )
            continue
        ranges = []
        for label in labels or []:
            for function in functions:
                if function.name != label["function_name"]:
                    continue
                segment = "".join(
                    source.splitlines(keepends=True)[function.lineno - 1 : function.end_lineno]
                )
                actual = hashlib.sha256(textwrap.dedent(segment).strip().encode()).hexdigest()
                if actual == label["normalized_code_before_sha256"]:
                    ranges.append((function.lineno, function.end_lineno, label))
        for sink in sinks:
            span = sink["span"]
            overlapping = sorted(changed_lines & set(range(span["startLine"], span["endLine"] + 1)))
            if not overlapping:
                continue
            matched_labels = [
                label
                for start, end, label in ranges
                if start <= span["startLine"] <= span["endLine"] <= end
            ]
            if labels and not matched_labels:
                outside_labels.append(
                    {"path": path, "span": span, "reason": "outside_exactly_matched_function_label"}
                )
                continue
            locations.append(
                {
                    "status": "resolved",
                    "path": path,
                    "span": span,
                    "sink_kind": sink["sink_kind"],
                    "callee": sink["callee"],
                    "provenance": {
                        **provenance,
                        "overlapping_patch_lines": overlapping,
                        "matched_function_labels": matched_labels,
                    },
                }
            )
    if not locations:
        unresolved.append(
            {
                "status": "known_location_unresolved",
                "reason": "no_sink_in_deleted_or_modified_lines_and_applicable_function_labels",
                "provenance": {
                    "kind": "PyVul_patch",
                    "fix_commit": manifest["fix_commit"],
                    "references": manifest["reference_provenance"],
                    "function_labels": label_provenance or {"status": "unavailable"},
                },
            }
        )
    return locations, unresolved, {"excluded_by_function_labels": outside_labels}


def extract_locations(
    pair_id: str,
    directory: Path = PAIRS,
    cache: Path = CACHE,
    *,
    dataset_path: Path | None = None,
    node="node",
):
    manifest, lock, snapshots = load_pair(pair_id, directory, cache)
    hunk_path = directory / pair_id / "patch-hunks.json"
    hunks = json.loads(hunk_path.read_text(encoding="utf-8"))
    expected_hashes = {version: lock[version]["sha256"] for version in snapshots}
    if hunks["pair_id"] != pair_id or hunks["snapshot_sha256"] != expected_hashes:
        raise ValueError("Patch hunks belong to different locked snapshots")
    if manifest["dataset"] == "SecBench.js":
        locations, unresolved, metadata = resolve_secbench(
            manifest, snapshots["vulnerable"][0], node=node
        )
    else:
        labels, provenance = function_labels(manifest, dataset_path)
        locations, unresolved, metadata = resolve_pyvul(
            manifest, snapshots["vulnerable"][0], hunks, labels=labels, label_provenance=provenance
        )
    result = {
        "pair_id": pair_id,
        "split": manifest["split"],
        "status": "resolved" if locations and not unresolved else "known_location_unresolved",
        "snapshot_sha256": expected_hashes,
        "patch_hunks_sha256": sha256(hunk_path),
        "generator_sha256": sha256(Path(__file__)),
        "locations": locations,
        "unresolved": unresolved,
        "resolved_location_count": len(locations),
        "unresolved_case_count": len(unresolved),
        "scanner_invocations": 0,
        **metadata,
    }
    write_json(directory / pair_id / "known-locations.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pair", action="append", required=True)
    parser.add_argument("--pairs", type=Path, default=PAIRS)
    parser.add_argument("--cache", type=Path, default=CACHE)
    parser.add_argument("--pyvul-functions-file", type=Path)
    parser.add_argument("--node", default="node")
    args = parser.parse_args()
    results = [
        extract_locations(
            pair_id, args.pairs, args.cache, dataset_path=args.pyvul_functions_file, node=args.node
        )
        for pair_id in args.pair
    ]
    print(
        json.dumps(
            {
                "pairs_inspected": len(results),
                "pairs_resolved": sum(result["status"] == "resolved" for result in results),
                "locations_resolved": sum(result["resolved_location_count"] for result in results),
                "unresolved_cases": sum(result["unresolved_case_count"] for result in results),
                "scanner_invocations": 0,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
