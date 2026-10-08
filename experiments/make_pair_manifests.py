"""Materialize only usable, row-in-scope pairs from the frozen v0.1 group split."""

# Direct CLI execution bootstraps the repository/backend before shared imports.
# ruff: noqa: E402

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from app.scanners.sources import validate_github, validate_npm

INVENTORY = ROOT / "experiments/inventory/pair-inventory.csv"
SPLIT = ROOT / "experiments/inventory/split_v0.1.json"
SCHEMA = ROOT / "experiments/schemas/pair-manifest.schema.json"
PAIRS = ROOT / "experiments/pairs"
VERSIONS = ("vulnerable", "fixed")


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
    )
    temporary.replace(path)


def source(row: dict[str, str], version: str) -> dict[str, str]:
    prefix = f"{version}_source."
    result = {
        key.removeprefix(prefix): value
        for key, value in row.items()
        if key.startswith(prefix) and value
    }
    if result["source_kind"] == "npm_tarball":
        validate_npm(result["package_name"], result["package_version"])
    elif result["source_kind"] == "github_tarball":
        owner, repo = result["repository"].split("/")
        validate_github(owner, repo, result["commit"])
    else:
        raise ValueError("Unsupported source kind")
    return result


def build_manifests(
    inventory: Path = INVENTORY, split_path: Path = SPLIT, schema_path: Path = SCHEMA
):
    with inventory.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    split = json.loads(split_path.read_text(encoding="utf-8"))
    if split["split_id"] != "split-v0.1" or split["status"] != "pre_scan_frozen":
        raise ValueError("Require the frozen split-v0.1")
    groups = {group["group_id"]: group for group in split["groups"]}
    if len(groups) != len(split["groups"]):
        raise ValueError("Duplicate split group")
    validator = Draft202012Validator(
        json.loads(schema_path.read_text(encoding="utf-8")), format_checker=FormatChecker()
    )
    manifests, excluded, seen = [], [], set()
    for row in sorted(rows, key=lambda item: item["pair_id"]):
        pair_id = row["pair_id"]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", pair_id) or pair_id in seen:
            raise ValueError(f"Unsafe or duplicate pair ID: {pair_id}")
        seen.add(pair_id)
        group = groups[row["group_id"]]
        if pair_id not in group["pair_ids"] or row["language"] != group["language"]:
            raise ValueError(f"Inventory/split membership mismatch: {pair_id}")
        assignment = group["assignment"]
        if (
            assignment == "excluded"
            or row["scope_verdict"] != "in_scope"
            or row["exclusion_reason"]
        ):
            excluded.append(
                {
                    "pair_id": pair_id,
                    "group_id": row["group_id"],
                    "group_assignment": assignment,
                    "inventory_split_v0": row["split"],
                    "scope_verdict": row["scope_verdict"],
                    "reason": row["exclusion_reason"]
                    or row["scope_reason"]
                    or group["scope_reason"],
                }
            )
            continue
        if assignment not in {"development", "held_out", "reserve"}:
            raise ValueError(f"Unexpected effective assignment: {assignment}")
        manifest = {
            key: row[key]
            for key in (
                "pair_id",
                "group_id",
                "dataset",
                "repository",
                "vulnerability_id",
                "language",
                "dataset_reported_category",
                "adjudicated_cwe",
                "scope_verdict",
                "scope_reason",
                "sink_kind",
                "os_command_execution_basis",
                "scope_review_provenance",
            )
        }
        for key in ("reported_cwes", "cwe_provenance", "reference_provenance"):
            manifest[key] = list(dict.fromkeys(value for value in row[key].split("|") if value))
        for key in ("vulnerable_ref", "fixed_ref", "fix_commit", "exclusion_reason"):
            manifest[key] = row[key] or None
        manifest["prior_exposure"] = row["prior_exposure"] == "true"
        manifest["split"] = assignment
        for version in VERSIONS:
            manifest[f"{version}_source"] = source(row, version)
        hint = re.search(r"SecBench sink ([^;]+:\d+:\d+)(?:;|$)", row["os_command_execution_basis"])
        if hint:
            manifest["sink_hint"] = hint[1]
        validator.validate(manifest)
        manifests.append(manifest)
    if seen != {pair_id for group in groups.values() for pair_id in group["pair_ids"]}:
        raise ValueError("Frozen split and inventory have different pair membership")
    counts = Counter(manifest["split"] for manifest in manifests)
    group_counts = Counter(
        assignment for _, assignment in {(m["group_id"], m["split"]) for m in manifests}
    )
    expected = Counter(
        {
            key: sum(values.get(key, 0) for values in split["summary_by_language"].values())
            for key in ("development", "held_out", "reserve")
        }
    )
    if group_counts != expected:
        raise ValueError(
            f"Manifest group counts differ from split-v0.1: {group_counts} != {expected}"
        )
    report = {
        "split_id": split["split_id"],
        "inputs_sha256": {
            "inventory": sha256(inventory),
            "split": sha256(split_path),
            "schema": sha256(schema_path),
        },
        "manifest_counts": dict(sorted(counts.items())),
        "group_counts": dict(sorted(group_counts.items())),
        "manifests": [m["pair_id"] for m in manifests],
        "excluded_count": len(excluded),
        "excluded": excluded,
    }
    return manifests, report


def load_manifests(directory: Path = PAIRS):
    index = json.loads((directory / "index.json").read_text(encoding="utf-8"))
    return [
        json.loads((directory / f"{pair_id}.json").read_text(encoding="utf-8"))
        for pair_id in index["manifests"]
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, default=INVENTORY)
    parser.add_argument("--split", type=Path, default=SPLIT)
    parser.add_argument("--schema", type=Path, default=SCHEMA)
    parser.add_argument("--output", type=Path, default=PAIRS)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    manifests, report = build_manifests(args.inventory, args.split, args.schema)
    for name, value in [(f"{m['pair_id']}.json", m) for m in manifests] + [("index.json", report)]:
        path = args.output / name
        if args.check:
            if json.loads(path.read_text(encoding="utf-8")) != value:
                raise ValueError(f"Stale generated file: {path}")
        else:
            write_json(path, value)
    print(
        json.dumps(
            {key: report[key] for key in ("manifest_counts", "group_counts", "excluded_count")},
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
