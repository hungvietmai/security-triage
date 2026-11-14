"""Before/after comparison tables from exported scan reports; no scanner, no network.

Input is what the application exports (`report.json`, see collect_report.py) plus, where a
label file exists, the expected result of each labeled site. Every configuration is counted on
the same unit, the review candidate (one call):

    semgrep, codeql, bandit, eslint   candidates that tool reported
    semgrep+codeql                    their union, merged by call
    all sources                       every candidate (the union of all detection tools)
    all sources, open-source filter   the main list if only rules whose evidence comes
                                      from an open-source tool (Semgrep, Bandit) filtered
    all sources, filtered             the main review list after evidence-based filtering
    first tiers (P1+P2), filtered     what a reviewer reads first; informational

A labeled site counts as reported by a configuration when any of its candidates is in it. A
candidate outside every labeled site is "unlabeled": it is counted, never scored. Precision,
recall and F1 are printed only when a label file is given.

    python experiments/evaluation/before_after.py <report-dir> [--labels FILE] [--json OUT]
"""

import argparse
import json
from pathlib import Path

TOOLS = ("semgrep", "codeql", "bandit", "eslint")
FIRST_TIERS = {"P1", "P2"}
# Filter rules whose evidence is produced by an open-source tool. G1 uses CodeQL, whose
# queries are open source but whose engine is not.
OPEN_SOURCE_RULES = {"G3_SEMGREP_DEAD_BRANCH", "G2_LITERAL_COMMAND"}


def filter_rules(candidate):
    """Every rule that filtered a candidate; older reports name only the first."""
    rules = candidate.get("filter_rules")
    if rules is None:
        rules = [candidate["filter_rule"]] if candidate.get("filter_rule") else []
    return rules


def configurations(candidates):
    """Name -> candidates in that configuration, in the order the tables print them."""
    tools = [tool for tool in TOOLS if any(tool in c["tools"] for c in candidates)]
    table = {tool: [c for c in candidates if tool in c["tools"]] for tool in tools}
    table["semgrep+codeql"] = [c for c in candidates if {"semgrep", "codeql"} & set(c["tools"])]
    table["all sources"] = list(candidates)
    table["all sources, open-source filter"] = [
        c for c in candidates if not OPEN_SOURCE_RULES & set(filter_rules(c))
    ]
    kept = [c for c in candidates if c["disposition"] == "review"]
    table["all sources, filtered"] = kept
    table["first tiers (P1+P2), filtered"] = [c for c in kept if c["priority"] in FIRST_TIERS]
    return table


def ratio(numerator, denominator):
    return round(numerator / denominator, 4) if denominator else None


def score(members, labels):
    """TP/FP/FN over labeled sites, and how many candidates fall outside the labels."""
    paths = {c["path"] for c in members}
    tp = sum(1 for path, vulnerable in labels.items() if vulnerable and path in paths)
    fp = sum(1 for path, vulnerable in labels.items() if not vulnerable and path in paths)
    fn = sum(1 for path, vulnerable in labels.items() if vulnerable and path not in paths)
    precision, recall = ratio(tp, tp + fp), ratio(tp, tp + fn)
    f1 = ratio(2 * tp, 2 * tp + fp + fn)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "unlabeled": sum(1 for c in members if c["path"] not in labels),
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def filter_effect(candidates, labels):
    """What filtering and demotion did to labeled true and false candidates."""

    def split(members):
        return {
            "true": sum(1 for c in members if labels.get(c["path"]) is True),
            "false": sum(1 for c in members if labels.get(c["path"]) is False),
            "unlabeled": sum(1 for c in members if c["path"] not in labels),
        }

    filtered = [c for c in candidates if c["disposition"] == "filtered"]
    kept = [c for c in candidates if c["disposition"] == "review"]
    return {
        "filtered": split(filtered),
        "filtered_by_rule": {
            # A candidate counts under every rule that filtered it.
            rule: split([c for c in filtered if rule in filter_rules(c)])
            for rule in sorted({rule for c in filtered for rule in filter_rules(c)})
        },
        "demoted_p3_p4": split([c for c in kept if c["priority"] not in FIRST_TIERS | {"U"}]),
        "first_tiers": split([c for c in kept if c["priority"] in FIRST_TIERS]),
    }


def seconds(report):
    """Wall-clock seconds per step, summed over languages; steps run partly in parallel."""
    totals = {}
    for steps in report["steps"].values():
        for name, record in steps.items():
            if isinstance(record.get("seconds"), (int, float)) and not name.endswith("-version"):
                totals[name] = round(totals.get(name, 0.0) + record["seconds"], 1)
    return totals


def evaluate(report, labels=None):
    candidates = report["candidates"]
    table = configurations(candidates)
    result = {
        "scan_status": report["status"],
        "profile": report["profile"],
        "snapshot_sha256": report["snapshot"]["sha256"],
        "source": report["snapshot"]["source_coordinate"],
        "tool_versions": report["tool_versions"],
        "stages": report["stages"],
        "sources": report["sources"],
        "candidates_per_configuration": {name: len(members) for name, members in table.items()},
        "step_seconds": seconds(report),
    }
    if labels is not None:
        result["labeled_sites"] = {
            "vulnerable": sum(labels.values()),
            "safe": len(labels) - sum(labels.values()),
        }
        result["scores"] = {name: score(members, labels) for name, members in table.items()}
        result["filter_effect"] = filter_effect(candidates, labels)
    return result


def _cell(value):
    return "n/a" if value is None else f"{value:.2f}" if isinstance(value, float) else str(value)


def markdown(result):
    lines = [
        f"Source `{result['source']}`, profile `{result['profile']}`, "
        f"scan `{result['scan_status']}`, snapshot `{result['snapshot_sha256'][:12]}…`.",
        "",
        "| Stage | Count |",
        "|---|---:|",
    ]
    lines += [f"| {name} | {count} |" for name, count in result["stages"].items()]
    if "scores" in result:
        sites = result["labeled_sites"]
        lines += [
            "",
            f"Labeled sites: {sites['vulnerable']} vulnerable, {sites['safe']} safe.",
            "",
            "| Configuration | Candidates | TP | FP | FN | Unlabeled | Precision | Recall | F1 |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
        for name, row in result["scores"].items():
            cells = [result["candidates_per_configuration"][name]]
            cells += [row[key] for key in ("tp", "fp", "fn", "unlabeled")]
            cells += [row[key] for key in ("precision", "recall", "f1")]
            lines.append(f"| {name} | " + " | ".join(_cell(cell) for cell in cells) + " |")
        effect = result["filter_effect"]
        lines += [
            "",
            "| Group after adjudication | True | False | Unlabeled |",
            "|---|---:|---:|---:|",
        ]
        groups = [("filtered (out of the main list)", effect["filtered"])]
        groups += [(f"  by {rule}", row) for rule, row in effect["filtered_by_rule"].items()]
        groups += [
            ("kept, first tiers P1+P2", effect["first_tiers"]),
            ("kept, demoted to P3/P4", effect["demoted_p3_p4"]),
        ]
        lines += [
            f"| {name} | {row['true']} | {row['false']} | {row['unlabeled']} |"
            for name, row in groups
        ]
    else:
        lines += ["", "| Configuration | Candidates |", "|---|---:|"]
        lines += [
            f"| {name} | {count} |"
            for name, count in result["candidates_per_configuration"].items()
        ]
    lines += ["", "| Tool | Candidates | Only this tool |", "|---|---:|---:|"]
    lines += [
        f"| {tool} | {row['candidates']} | {row['only']} |"
        for tool, row in result["sources"].items()
    ]
    lines += ["", "| Step | Seconds |", "|---|---:|"]
    lines += [f"| {name} | {value} |" for name, value in result["step_seconds"].items()]
    return "\n".join(lines) + "\n"


def load_labels(path):
    """{site path: expected_vulnerable} from an expectations file with a `cases` list."""
    cases = json.loads(Path(path).read_bytes())["cases"]
    return {case["path"]: bool(case["expected_vulnerable"]) for case in cases}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("report_dir", type=Path)
    parser.add_argument("--labels", type=Path)
    parser.add_argument("--json", type=Path, help="also write the result as JSON")
    args = parser.parse_args(argv)
    report = json.loads((args.report_dir / "report.json").read_bytes())
    result = evaluate(report, load_labels(args.labels) if args.labels else None)
    if args.json:
        args.json.write_bytes((json.dumps(result, indent=2, ensure_ascii=False) + "\n").encode())
    print(markdown(result), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
