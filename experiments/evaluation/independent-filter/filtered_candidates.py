"""What the filter step did on sources without labels: counts per scan and every filtered call.

The sources of this check have no known vulnerability, so nothing is scored as true or false
here. The script reports, from the exported reports only: the status of each scan, how many
candidates each produced, how many the filter moved out of the main list and by which rule,
and the list of filtered candidates for the check in verify_filtered.py.

    python experiments/evaluation/independent-filter/filtered_candidates.py \
        <sources.json> <inputs-dir> [--json OUT]
"""

import argparse
import json
from pathlib import Path

STAGES = ("raw_alerts", "units", "candidates", "main_list", "filtered", "demoted")


def evaluate(sources, inputs):
    rows, filtered = [], []
    for source in sources["sources"]:
        report_file = Path(inputs) / source["id"] / "report.json"
        if not report_file.is_file():
            rows.append({"id": source["id"], "scan_status": "missing"})
            continue
        report = json.loads(report_file.read_bytes())
        rows.append(
            {
                "id": source["id"],
                "source": report["snapshot"]["source_coordinate"],
                "snapshot_sha256": report["snapshot"]["sha256"],
                "scan_status": report["status"],
                "stages": {name: report["stages"][name] for name in STAGES},
                "tools": report["sources"],
                "filtered_by_rule": report["filtered_by_rule"],
                "main_list_by_priority": report["main_list_by_priority"],
            }
        )
        for candidate in report["candidates"]:
            if candidate["disposition"] != "filtered":
                continue
            filtered.append(
                {
                    "id": source["id"],
                    "owner": source["owner"],
                    "repo": source["repo"],
                    "commit": source["commit"],
                    "scan_status": report["status"],
                    "path": candidate["path"],
                    "line": candidate["start_line"],
                    "sink_kind": candidate["sink_kind"],
                    "tools": candidate["tools"],
                    "priority": candidate["priority"],
                    "filter_rules": candidate.get("filter_rules") or [],
                }
            )
    statuses, by_rule = {}, {}
    totals = dict.fromkeys(STAGES, 0)
    for row in rows:
        statuses[row["scan_status"]] = statuses.get(row["scan_status"], 0) + 1
        for name in STAGES:
            totals[name] += row.get("stages", {}).get(name, 0)
    for item in filtered:
        for rule in item["filter_rules"]:
            by_rule[rule] = by_rule.get(rule, 0) + 1
    completed = [row for row in rows if row["scan_status"] == "completed"]
    return {
        "scan_statuses": statuses,
        "totals": totals,
        "completed_scans": {
            "scans": len(completed),
            "candidates": sum(row["stages"]["candidates"] for row in completed),
            "filtered": sum(row["stages"]["filtered"] for row in completed),
            "with_a_filtered_candidate": sum(1 for row in completed if row["stages"]["filtered"]),
        },
        "filtered_by_rule": by_rule,
        "sources": rows,
        "filtered": filtered,
    }


def markdown(result):
    lines = [
        f"Scan statuses: {result['scan_statuses']}. Totals: {result['totals']}.",
        f"Completed scans: {result['completed_scans']}. Filtered by rule: "
        f"{result['filtered_by_rule']}.",
        "",
        "| Source | Scan | " + " | ".join(STAGES) + " | Filtered by rule |",
        "|---|---|" + "---:|" * len(STAGES) + "---|",
    ]
    for row in result["sources"]:
        stages = row.get("stages")
        cells = [str(stages[name]) for name in STAGES] if stages else ["—"] * len(STAGES)
        rules = row.get("filtered_by_rule") or ""
        lines.append(
            f"| {row['id']} | {row['scan_status']} | " + " | ".join(cells) + f" | {rules} |"
        )
    lines += [
        "",
        "| Filtered candidate | Call | Tools | Priority | Rules |",
        "|---|---|---|---|---|",
    ]
    for item in result["filtered"]:
        lines.append(
            f"| {item['id']} `{item['path']}:{item['line']}` | {item['sink_kind']} | "
            f"{', '.join(item['tools'])} | {item['priority']} | {', '.join(item['filter_rules'])} |"
        )
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("sources", type=Path)
    parser.add_argument("inputs", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv)
    result = evaluate(json.loads(args.sources.read_bytes()), args.inputs)
    if args.json:
        args.json.write_bytes((json.dumps(result, indent=2, ensure_ascii=False) + "\n").encode())
    print(markdown(result), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
