#!/usr/bin/env python3
"""
Deterministic group split generator and verifier.

Key guarantees:
- split-v0 is derived from immutable group attributes plus prior_exposure.
- generated split values in the inventory are never used as exposure evidence.
- the script never mutates the inventory.
- --check compares a freshly generated split-v0 with the frozen artifact.
- --derive-v0-1 applies pre-scan scope verdicts to frozen split-v0 without
  redrawing hash order or replacing held-out groups.
"""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import math
import sys
from collections import defaultdict
from pathlib import Path

PRIMARY_CWES = {"CWE-77", "CWE-78", "CWE-88"}
DEFAULT_INVENTORY = Path("experiments/inventory/pair-inventory.csv")
DEFAULT_BASE = Path("experiments/inventory/split_v0.json")
DEFAULT_V01 = Path("experiments/inventory/split_v0.1.json")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    p.add_argument("--output", type=Path, default=DEFAULT_BASE)
    p.add_argument("--check", action="store_true", help="compare regenerated split-v0 with --output; do not write")
    p.add_argument("--derive-v0-1", action="store_true", help="derive scope-filtered split-v0.1 from frozen split-v0")
    p.add_argument("--base-split", type=Path, default=DEFAULT_BASE)
    p.add_argument("--derived-output", type=Path, default=DEFAULT_V01)
    return p.parse_args()


def digest(group_id: str) -> str:
    return hashlib.sha256(group_id.encode("utf-8")).hexdigest()


def parse_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "y"}


def load_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise RuntimeError("inventory header missing")
        rows = list(reader)
    if "prior_exposure" not in reader.fieldnames:
        raise RuntimeError("inventory must contain prior_exposure")
    return rows


def grouped(rows: list[dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    groups: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        gid = row["group_id"].strip()
        if not gid:
            raise RuntimeError(f"missing group_id for {row.get('pair_id')}")
        groups[gid].append(row)
    return groups


def source_excluded(members: list[dict[str, str]]) -> bool:
    # Source/provenance exclusions predate split generation and remain recorded
    # by split=excluded plus an exclusion reason. Generated development/held_out
    # assignments are deliberately ignored.
    return any(r["split"] == "excluded" and r.get("exclusion_reason", "").strip() for r in members)


def base_group_status(members: list[dict[str, str]]) -> tuple[str, str]:
    if source_excluded(members):
        reasons = sorted({r["exclusion_reason"] for r in members if r["split"] == "excluded" and r["exclusion_reason"]})
        return "excluded", "; ".join(reasons) or "pre-existing source/provenance exclusion"

    if any(parse_bool(r.get("prior_exposure", "")) for r in members):
        return "development", "previously exposed group"

    cwes = {r["adjudicated_cwe"].strip() for r in members}
    if "cwe_unresolved" in cwes:
        return "reserve", "contains cwe_unresolved"
    outside = sorted(cwe for cwe in cwes if cwe not in PRIMARY_CWES)
    if outside:
        return "reserve", "outside primary CWE family: " + ",".join(outside)

    return "eligible", "fresh primary-family group"


def build_base_split(rows: list[dict[str, str]]) -> dict:
    groups = grouped(rows)
    records: dict[str, dict] = {}
    fresh_by_language: dict[str, list[str]] = defaultdict(list)

    for gid, members in sorted(groups.items()):
        languages = {r["language"] for r in members}
        if len(languages) != 1:
            raise RuntimeError(f"{gid}: mixed languages {sorted(languages)}")
        language = next(iter(languages))
        status, reason = base_group_status(members)
        rec = {
            "group_id": gid,
            "language": language,
            "dataset": sorted({r["dataset"] for r in members}),
            "pair_ids": sorted(r["pair_id"] for r in members),
            "adjudicated_cwes": sorted({r["adjudicated_cwe"] for r in members}),
            "hash_sha256": digest(gid),
            "assignment": status,
            "reason": reason,
        }
        records[gid] = rec
        if status == "eligible":
            fresh_by_language[language].append(gid)

    strata: dict[str, dict] = {}
    for language in sorted(fresh_by_language):
        ordered = sorted(fresh_by_language[language], key=lambda gid: (records[gid]["hash_sha256"], gid))
        held_count = math.ceil(len(ordered) * 0.40)
        held = set(ordered[:held_count])
        for gid in ordered:
            if gid in held:
                records[gid]["assignment"] = "held_out"
                records[gid]["reason"] = "fresh eligible group selected in first ceil(40%) of SHA-256 order"
            else:
                records[gid]["assignment"] = "development"
                records[gid]["reason"] = "fresh eligible group outside first ceil(40%) of SHA-256 order"
        strata[language] = {
            "fresh_eligible_groups": len(ordered),
            "held_out_groups": held_count,
            "development_groups_from_hash": len(ordered) - held_count,
            "held_out_fraction": held_count / len(ordered) if ordered else 0.0,
            "ordered_group_ids": ordered,
        }

    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for rec in records.values():
        counts[rec["language"]][rec["assignment"]] += 1

    return {
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
        "summary_by_language": {lang: dict(sorted(v.items())) for lang, v in sorted(counts.items())},
        "strata": strata,
        "groups": [records[gid] for gid in sorted(records)],
    }


def derive_v01(base: dict, rows: list[dict[str, str]]) -> dict:
    by_group = grouped(rows)
    derived_groups = []
    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    held_cwe: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    removed_held_out: list[str] = []

    for frozen in base["groups"]:
        gid = frozen["group_id"]
        members = by_group[gid]
        frozen_assignment = frozen["assignment"]

        if frozen_assignment == "excluded":
            effective = "excluded"
            scope_state = "not_reviewed_source_excluded"
            scope_reason = "pre-existing source/provenance exclusion"
            in_scope_cwes: list[str] = []
        else:
            verdicts = [r.get("scope_verdict", "").strip() for r in members if r.get("scope_verdict", "").strip()]
            in_scope_rows = [r for r in members if r.get("scope_verdict", "").strip() == "in_scope"]
            unresolved_rows = [r for r in members if r.get("scope_verdict", "").strip() in {"", "unresolved"}]

            if in_scope_rows:
                scope_state = "in_scope"
                scope_reason = "at least one pair row remains in scope"
                effective = frozen_assignment
                in_scope_cwes = sorted({r["adjudicated_cwe"] for r in in_scope_rows if r["adjudicated_cwe"] in PRIMARY_CWES})
            elif unresolved_rows:
                scope_state = "unresolved"
                scope_reason = "no in-scope row and at least one unresolved row"
                effective = "reserve"
                in_scope_cwes = []
            else:
                scope_state = "out_of_scope"
                scope_reason = "all reviewed pair rows are out of scope"
                effective = "excluded"
                in_scope_cwes = []

        if frozen_assignment == "held_out" and effective != "held_out":
            removed_held_out.append(gid)

        rec = copy.deepcopy(frozen)
        rec["frozen_assignment"] = frozen_assignment
        rec["assignment"] = effective
        rec["scope_state"] = scope_state
        rec["scope_reason"] = scope_reason
        rec["in_scope_cwes"] = in_scope_cwes
        rec["replacement_group_id"] = None
        derived_groups.append(rec)
        counts[rec["language"]][effective] += 1

        if effective == "held_out":
            for cwe in in_scope_cwes:
                held_cwe[rec["language"]][cwe].add(gid)

    return {
        "split_id": "split-v0.1",
        "status": "pre_scan_frozen",
        "date": "2026-10-05",
        "derived_from": {
            "split_id": base["split_id"],
            "tag": "split-v0",
            "freeze_commit": "72972469ea7b8da895ba4a3bdc2309676b04a953",
        },
        "selection_redrawn": False,
        "replacement_performed": False,
        "scope_filter_only": True,
        "unit": "group_id",
        "primary_cwes": sorted(PRIMARY_CWES),
        "stratification": base["stratification"],
        "hash": base["hash"],
        "held_out_rule": base["held_out_rule"],
        "frozen_strata": base["strata"],
        "summary_by_language": {lang: dict(sorted(v.items())) for lang, v in sorted(counts.items())},
        "held_out_groups_by_language_and_cwe": {
            lang: {cwe: sorted(gids) for cwe, gids in sorted(cwes.items())}
            for lang, cwes in sorted(held_cwe.items())
        },
        "removed_or_reserved_from_frozen_held_out": sorted(removed_held_out),
        "groups": sorted(derived_groups, key=lambda x: x["group_id"]),
    }


def normalized(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def main() -> int:
    args = parse_args()
    rows = load_rows(args.inventory)

    if args.derive_v0_1:
        base = json.loads(args.base_split.read_text(encoding="utf-8"))
        result = derive_v01(base, rows)
        args.derived_output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({
            "split_id": result["split_id"],
            "summary_by_language": result["summary_by_language"],
            "removed_or_reserved_from_frozen_held_out": result["removed_or_reserved_from_frozen_held_out"],
        }, sort_keys=True))
        return 0

    generated = build_base_split(rows)

    if args.check:
        existing = json.loads(args.output.read_text(encoding="utf-8"))
        if normalized(generated) != normalized(existing):
            print("split-v0 check failed: regenerated artifact differs from frozen artifact", file=sys.stderr)
            return 1
        print("split-v0 check passed")
        return 0

    args.output.write_text(json.dumps(generated, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"split_id": generated["split_id"], "summary_by_language": generated["summary_by_language"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
