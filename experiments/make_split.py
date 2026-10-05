#!/usr/bin/env python3
"""
Create deterministic development/held-out/reserve/excluded splits at group level.

Rules frozen for split-v0:
- group unit is group_id from GROUPING.md
- stratify only by language
- preserve explicit development exposure
- explicit excluded rows remain excluded
- groups with cwe_unresolved, non-family CWE, unresolved scope, or out-of-scope
  rows do not enter the held-out draw
- among fresh eligible groups, sort by SHA-256(group_id) within each language
- first ceil(40%) become held_out; remaining groups become development
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from collections import defaultdict
from pathlib import Path

PRIMARY_CWES = {"CWE-77", "CWE-78", "CWE-88"}
DEFAULT_INVENTORY = Path("experiments/inventory/pair-inventory.csv")
DEFAULT_OUTPUT = Path("experiments/inventory/split_v0.json")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return p.parse_args()


def digest(group_id: str) -> str:
    return hashlib.sha256(group_id.encode("utf-8")).hexdigest()


def group_reason(rows: list[dict[str, str]]) -> tuple[str, str]:
    splits = {r["split"] for r in rows}

    if "excluded" in splits:
        reasons = sorted({r["exclusion_reason"] for r in rows if r["split"] == "excluded" and r["exclusion_reason"]})
        return "excluded", "; ".join(reasons) or "pre-existing exclusion"

    # Prior exposure is sticky at group level.
    if "development" in splits:
        return "development", "previously exposed group"

    scope_values = {r.get("scope_verdict", "").strip() for r in rows if r.get("scope_verdict", "").strip()}
    if "out_of_scope" in scope_values:
        return "excluded", "explicit scope_verdict=out_of_scope"
    if "unresolved" in scope_values:
        return "reserve", "scope unresolved"

    cwes = {r["adjudicated_cwe"].strip() for r in rows}
    if "cwe_unresolved" in cwes:
        return "reserve", "contains cwe_unresolved"
    outside = sorted(cwe for cwe in cwes if cwe not in PRIMARY_CWES)
    if outside:
        return "reserve", "outside primary CWE family: " + ",".join(outside)

    return "eligible", "fresh primary-family group"


def main() -> int:
    args = parse_args()

    with args.inventory.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise RuntimeError("inventory header missing")
        fieldnames = reader.fieldnames
        rows = list(reader)

    groups: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        group_id = row["group_id"].strip()
        if not group_id:
            raise RuntimeError(f"missing group_id for {row.get('pair_id')}")
        groups[group_id].append(row)

    records: dict[str, dict] = {}
    fresh_by_language: dict[str, list[str]] = defaultdict(list)

    for group_id, members in sorted(groups.items()):
        languages = {r["language"] for r in members}
        if len(languages) != 1:
            raise RuntimeError(f"{group_id}: mixed languages {sorted(languages)}")
        language = next(iter(languages))
        status, reason = group_reason(members)

        record = {
            "group_id": group_id,
            "language": language,
            "dataset": sorted({r["dataset"] for r in members}),
            "pair_ids": sorted(r["pair_id"] for r in members),
            "adjudicated_cwes": sorted({r["adjudicated_cwe"] for r in members}),
            "hash_sha256": digest(group_id),
            "assignment": status,
            "reason": reason,
        }
        records[group_id] = record
        if status == "eligible":
            fresh_by_language[language].append(group_id)

    strata: dict[str, dict] = {}
    for language in sorted(fresh_by_language):
        ordered = sorted(fresh_by_language[language], key=lambda gid: (records[gid]["hash_sha256"], gid))
        held_out_count = math.ceil(len(ordered) * 0.40)
        held_out = set(ordered[:held_out_count])

        for group_id in ordered:
            if group_id in held_out:
                records[group_id]["assignment"] = "held_out"
                records[group_id]["reason"] = "fresh eligible group selected in first ceil(40%) of SHA-256 order"
            else:
                records[group_id]["assignment"] = "development"
                records[group_id]["reason"] = "fresh eligible group outside first ceil(40%) of SHA-256 order"

        strata[language] = {
            "fresh_eligible_groups": len(ordered),
            "held_out_groups": held_out_count,
            "development_groups_from_hash": len(ordered) - held_out_count,
            "held_out_fraction": held_out_count / len(ordered) if ordered else 0.0,
            "ordered_group_ids": ordered,
        }

    # Apply group assignment back to every row.
    for row in rows:
        row["split"] = records[row["group_id"]]["assignment"]
        if row["split"] == "excluded" and not row["exclusion_reason"]:
            row["exclusion_reason"] = records[row["group_id"]]["reason"]

    with args.inventory.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    counts = defaultdict(lambda: defaultdict(int))
    for record in records.values():
        counts[record["language"]][record["assignment"]] += 1

    payload = {
        "split_id": "split-v0",
        "status": "pre_scan_frozen",
        "date": "2026-10-05",
        "unit": "group_id",
        "primary_cwes": sorted(PRIMARY_CWES),
        "stratification": ["language"],
        "hash": {
            "algorithm": "sha256",
            "input": "UTF-8 group_id",
            "tie_break": "group_id lexical order",
        },
        "held_out_rule": {
            "fraction": 0.40,
            "count_rule": "ceil(fresh_eligible_groups * 0.40) per language",
            "selection": "first groups in ascending SHA-256 order",
        },
        "special_handling": {
            "pre_exposed_group": "development",
            "cwe_unresolved": "reserve",
            "non_primary_cwe": "reserve",
            "scope_unresolved": "reserve",
            "scope_out_of_scope": "excluded",
            "pre_existing_excluded": "excluded",
        },
        "summary_by_language": {lang: dict(sorted(values.items())) for lang, values in sorted(counts.items())},
        "strata": strata,
        "groups": [records[group_id] for group_id in sorted(records)],
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")

    print(json.dumps({
        "groups": len(records),
        "summary_by_language": payload["summary_by_language"],
        "fresh_strata": {
            language: {
                "fresh_eligible_groups": value["fresh_eligible_groups"],
                "held_out_groups": value["held_out_groups"],
            }
            for language, value in strata.items()
        },
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
