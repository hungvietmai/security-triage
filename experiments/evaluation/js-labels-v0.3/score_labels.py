"""Score the v0.3 exports of the 84 npm sources against labels of their JavaScript candidates.

A unit is one line of one JavaScript or TypeScript file on which a candidate starts. Its label
is `vulnerable` when it is a known vulnerable site (CVE labels) and otherwise the label of
labels.json: `vulnerable`, `safe` or `undetermined`. See PROTOCOL.md for who assigned them.

    python experiments/evaluation/js-labels-v0.3/score_labels.py [--json OUT]
"""

import argparse
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIRST_TIERS = {"P1", "P2"}
TIER_ORDER = ("P1", "P2", "U", "P3", "P4")
LABELS = ("vulnerable", "safe", "undetermined")


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _ratio(numerator, denominator):
    return round(numerator / denominator, 4) if denominator else None


def configurations():
    def tools(*names):
        wanted = set(names)
        return lambda unit: bool(wanted & set(unit["tools"]))

    def kept(unit):
        return not unit["filtered"]

    return {
        "semgrep": tools("semgrep"),
        "codeql": tools("codeql"),
        "eslint": tools("eslint"),
        "semgrep ∪ codeql": tools("semgrep", "codeql"),
        "all sources": lambda unit: True,
        "all sources, after filtering": kept,
        "first tiers (P1+P2), after filtering": lambda u: kept(u) and u["priority"] in FIRST_TIERS,
    }


def merge(candidates):
    """One unit from the candidates that start on one line."""
    kept = [c for c in candidates if c["disposition"] != "filtered"]
    ranked = sorted(kept or candidates, key=lambda c: TIER_ORDER.index(c["priority"]))
    return {
        "tools": sorted({tool for c in candidates for tool in c["tools"]}),
        "filtered": not kept,
        "priority": ranked[0]["priority"],
        "filter_rules": sorted({rule for c in candidates for rule in c.get("filter_rules") or []}),
    }


def score(units, missed_known):
    """Counts and rates over labeled units; `missed_known` known sites have no candidate."""
    vulnerable_total = sum(1 for u in units if u["label"] == "vulnerable") + missed_known
    table = {}
    for name, member in configurations().items():
        inside = [u for u in units if member(u)]
        tp = sum(1 for u in inside if u["label"] == "vulnerable")
        fp = sum(1 for u in inside if u["label"] == "safe")
        precision, recall = _ratio(tp, tp + fp), _ratio(tp, vulnerable_total)
        f1 = (
            round(2 * precision * recall / (precision + recall), 4)
            if precision and recall
            else None
        )
        table[name] = {
            "tp": tp,
            "fp": fp,
            "undetermined": sum(1 for u in inside if u["label"] == "undetermined"),
            "fn": vulnerable_total - tp,
            "precision": precision,
            "recall_upper_bound": recall,
            "f1_upper_bound": f1,
        }
    filtered = [u for u in units if u["filtered"]]
    safe_kept = [u for u in units if u["label"] == "safe" and not u["filtered"]]
    by_class, by_tier = {}, {}
    for unit in safe_kept:
        by_class[unit["class"]] = by_class.get(unit["class"], 0) + 1
        by_tier[unit["priority"]] = by_tier.get(unit["priority"], 0) + 1
    return {
        "units": len(units),
        "labels": {
            label: {
                source: sum(1 for u in units if u["label"] == label and u["source"] == source)
                for source in ("cve", "assistant")
            }
            for label in LABELS
        },
        "known_sites_without_candidate": missed_known,
        "configurations": table,
        "filter": {label: sum(1 for u in filtered if u["label"] == label) for label in LABELS},
        "filter_rules": sorted({rule for u in filtered for rule in u["filter_rules"]}),
        "safe_left_in_review_list": {
            "total": len(safe_kept),
            "by_class": dict(sorted(by_class.items())),
            "by_priority": {tier: by_tier.get(tier, 0) for tier in TIER_ORDER},
        },
    }


def build_units():
    """(units, missed known sites) per group from the saved exports and labels.json."""
    sheet = _load("label_sheet", HERE / "label_sheet.py")
    known = _load("js_matching_compare", sheet.MATCHING / "compare.py").known_sites()
    labels = {row["id"]: row for row in json.loads((HERE / "labels.json").read_bytes())["labels"]}
    groups = {"all": ([], 0), "not_read_when_fixing": ([], 0)}
    used = set()
    for source in sheet.sources():
        sites = set(known.get(f"{source['package']}@{source['version']}", []))
        by_line = {}
        for candidate in sheet.javascript_candidates(source):
            by_line.setdefault((candidate["path"], candidate["start_line"]), []).append(candidate)
        units = []
        # An unmatched alert has no line; sort it first within its file.
        ordered = sorted(by_line.items(), key=lambda item: (item[0][0], item[0][1] or 0))
        for (path, line), candidates in ordered:
            unit = merge(candidates)
            if (path, line) in sites:
                unit.update(label="vulnerable", source="cve", **{"class": None})
            else:
                label = labels[f"{source['id']}|{path}|{line}"]
                used.add(label["id"])
                unit.update(label=label["label"], source="assistant", **{"class": label["class"]})
            unit.update(id=f"{source['id']}|{path}|{line}")
            units.append(unit)
        missed = len(sites - set(by_line))
        names = ["all"] + ([] if source["used_to_fix"] else ["not_read_when_fixing"])
        for name in names:
            groups[name] = (groups[name][0] + units, groups[name][1] + missed)
    unused = sorted(set(labels) - used)
    if unused:
        raise SystemExit(f"labels without a candidate: {unused[:5]}")
    return groups


def evaluate():
    meta = json.loads((HERE / "labels.json").read_bytes())
    return {
        "labels_assigned_by": meta["assigned_by"],
        "labels_reviewed_by": meta["reviewed_by"],
        "groups": {name: score(units, missed) for name, (units, missed) in build_units().items()},
    }


def _print(result):
    reviewed = result["labels_reviewed_by"] or "nobody yet"
    print(f"Labels assigned by: {result['labels_assigned_by']}; reviewed by: {reviewed}.")
    for name, group in result["groups"].items():
        print(f"\n### {name}: {group['units']} units, labels {group['labels']}")
        print(f"Known sites without a candidate: {group['known_sites_without_candidate']}\n")
        print("| Configuration | TP | FP | Undetermined | FN | Precision | Recall ≤ | F1 ≤ |")
        print("|---|---:|---:|---:|---:|---:|---:|---:|")
        for config, row in group["configurations"].items():
            print(
                f"| {config} | {row['tp']} | {row['fp']} | {row['undetermined']} | {row['fn']} "
                f"| {row['precision']} | {row['recall_upper_bound']} | {row['f1_upper_bound']} |"
            )
        print(f"\nFiltered: {group['filter']} by {group['filter_rules']}")
        print(f"Safe units left in the review list: {group['safe_left_in_review_list']}")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv)
    result = evaluate()
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
        args.json.write_bytes(data.encode())
    _print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
