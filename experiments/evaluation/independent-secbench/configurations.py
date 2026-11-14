"""Before/after comparison on documented vulnerable sites of sources scanned once.

Scores every source with ../independent/known_sites.py (unchanged) and adds what that script
does not print: how many documented sites each configuration reports, so that Semgrep alone,
CodeQL alone, their union, the union of every source and the list after filtering are compared
on the same sites. Positives only, so it reports coverage and lost true positives, never
precision.

    python experiments/evaluation/independent-secbench/configurations.py \
        <labels.json> <inputs-dir> [--json OUT]
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "independent"))
import known_sites  # noqa: E402

DETECTORS = ("semgrep", "codeql", "eslint", "bandit")
# A configuration is the set of tools whose candidates a reviewer would see.
CONFIGURATIONS = {
    "semgrep": {"semgrep"},
    "codeql": {"codeql"},
    "eslint": {"eslint"},
    "semgrep ∪ codeql": {"semgrep", "codeql"},
    "all sources": set(DETECTORS),
}
VERSION_STEP = "-version"


def site_rows(result):
    for source in result["sources"]:
        for site in source["sites"]:
            yield source, site


def configuration_counts(result):
    """Documented sites each configuration reports, over the sources that were scanned."""
    scanned = [(s, site) for s, site in site_rows(result) if s["scan_status"] == "completed"]
    counts = {}
    for name, tools in CONFIGURATIONS.items():
        counts[name] = sum(1 for _, site in scanned if tools & set(site["tools"]))
    reported = [site for _, site in scanned if site["reported"]]
    counts["all sources, after filtering"] = sum(1 for site in reported if not site["filtered"])
    counts["first tiers (P1+P2), after filtering"] = sum(
        1 for site in reported if not site["filtered"] and site["in_first_tiers"]
    )
    only = {tool: sum(1 for site in reported if site["tools"] == [tool]) for tool in DETECTORS}
    priorities = {
        tier: sum(1 for site in reported if not site["filtered"] and site["priority"] == tier)
        for tier in known_sites.TIERS
    }
    return {
        "documented_sites_scanned": len(scanned),
        "reported_by_configuration": counts,
        "reported_by_one_tool_only": only,
        "lost_to_filtering": sum(1 for site in reported if site["filtered"]),
        "kept_sites_by_priority": priorities,
    }


def unlabeled_totals(result):
    """Candidates outside every documented site: workload, never scored."""
    totals = {
        "total": 0,
        "filtered": 0,
        "main_list_by_priority": dict.fromkeys(known_sites.TIERS, 0),
    }
    for source in result["sources"]:
        unlabeled = source.get("unlabeled")
        if not unlabeled:
            continue
        totals["total"] += unlabeled["total"]
        totals["filtered"] += len(unlabeled["filtered"])
        for tier, count in unlabeled["main_list_by_priority"].items():
            totals["main_list_by_priority"][tier] += count
    return totals


def scan_seconds(report):
    """Wall time of the scan and the summed tool steps, version checks left out."""
    started, finished = report.get("started_at"), report.get("finished_at")
    wall = None
    if started and finished:
        wall = round(
            (datetime.fromisoformat(finished) - datetime.fromisoformat(started)).total_seconds(), 1
        )
    steps = {}
    for language in (report.get("steps") or {}).values():
        for step, record in language.items():
            if step.endswith(VERSION_STEP) or "seconds" not in record:
                continue
            steps[step] = round(steps.get(step, 0.0) + record["seconds"], 1)
    return {"wall": wall, "steps": steps}


def evaluate(labels, inputs):
    result = known_sites.evaluate(labels, inputs)
    statuses = {}
    for source in result["sources"]:
        statuses[source["scan_status"]] = statuses.get(source["scan_status"], 0) + 1
        report_file = Path(inputs) / source["id"] / "report.json"
        if not report_file.is_file():
            continue
        report = json.loads(report_file.read_bytes())
        source["seconds"] = scan_seconds(report)
        for site in source["sites"]:
            # Shown for a site that is not reported, so that a call the tools report one line
            # away is visible. It never changes whether the site counts as reported.
            site["same_file_candidate_lines"] = sorted(
                c["start_line"]
                for c in report["candidates"]
                if c["path"] == site["path"] and c["start_line"] is not None
            )
    result["scan_statuses"] = statuses
    result["configurations"] = configuration_counts(result)
    result["unlabeled"] = unlabeled_totals(result)
    walls = [s["seconds"]["wall"] for s in result["sources"] if s.get("seconds", {}).get("wall")]
    result["wall_seconds"] = {
        "scans": len(walls),
        "total": round(sum(walls), 1),
        "median": sorted(walls)[len(walls) // 2] if walls else None,
        "max": max(walls) if walls else None,
    }
    return result


def markdown(result):
    block = result["configurations"]
    scanned = block["documented_sites_scanned"]
    lines = [
        f"Sources: {len(result['sources'])}; scan status: {result['scan_statuses']}.",
        f"Documented sites in completed scans: {scanned}.",
        "",
        "| Configuration | Documented sites reported | Share |",
        "|---|---:|---:|",
    ]
    for name, count in block["reported_by_configuration"].items():
        share = f"{count / scanned:.2f}" if scanned else "—"
        lines.append(f"| {name} | {count} | {share} |")
    lines += [
        "",
        f"Documented sites lost to filtering: {block['lost_to_filtering']}.",
        f"Reported by one tool only: {block['reported_by_one_tool_only']}.",
        f"Kept documented sites by priority: {block['kept_sites_by_priority']}.",
        f"Unlabeled candidates: {result['unlabeled']}.",
        f"Scan wall time (s): {result['wall_seconds']}.",
        "",
    ]
    return "\n".join(lines) + known_sites.markdown(result)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("labels", type=Path)
    parser.add_argument("inputs", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv)
    result = evaluate(json.loads(args.labels.read_bytes()), args.inputs)
    if args.json:
        args.json.write_bytes((json.dumps(result, indent=2, ensure_ascii=False) + "\n").encode())
    print(markdown(result), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
