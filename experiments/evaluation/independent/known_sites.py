"""Score saved scan reports against documented vulnerable sites (positives only).

For every source in a label file: is each documented site reported, by which tools, at which
priority, and did filtering keep it in the main review list. Candidates that match no documented
site are unlabeled: they are counted by disposition and priority and never scored, so this
script reports no precision.

    python experiments/evaluation/independent/known_sites.py <labels.json> <inputs-dir> [--json OUT]

`<inputs-dir>/<source id>/report.json` is an exported report (see ../collect_report.py).
"""

import argparse
import json
from pathlib import Path

TIERS = ("P1", "P2", "U", "P3", "P4")
FIRST_TIERS = {"P1", "P2"}


def score_source(source, report):
    """One source: each documented site with its candidate, and the unlabeled remainder."""
    candidates = report["candidates"]
    matched = set()
    sites = []
    for site in source["sites"]:
        # A candidate is one call; its start line is the line the call begins on.
        found = [
            c for c in candidates if c["path"] == site["path"] and c["start_line"] == site["line"]
        ]
        matched.update(c["candidate_key"] for c in found)
        best = min(found, key=lambda c: TIERS.index(c["priority"])) if found else None
        sites.append(
            {
                "path": site["path"],
                "line": site["line"],
                "basis": site["basis"],
                "reported": bool(found),
                "tools": sorted({tool for c in found for tool in c["tools"]}),
                "priority": best["priority"] if best else None,
                "in_first_tiers": bool(best and best["priority"] in FIRST_TIERS),
                # A documented vulnerability that filtering removed is a lost true positive.
                "filtered": bool(found) and all(c["disposition"] == "filtered" for c in found),
                "filter_rules": sorted({r for c in found for r in c.get("filter_rules", [])}),
            }
        )
    unlabeled = [c for c in candidates if c["candidate_key"] not in matched]
    return {
        "id": source["id"],
        "source": report["snapshot"]["source_coordinate"],
        "snapshot_sha256": report["snapshot"]["sha256"],
        "scan_status": report["status"],
        "profile": report["profile"],
        "profile_sha256": report.get("profile_sha256"),
        "stages": report["stages"],
        "sites": sites,
        "unlabeled": {
            "total": len(unlabeled),
            "main_list_by_priority": {
                tier: sum(
                    1 for c in unlabeled if c["disposition"] == "review" and c["priority"] == tier
                )
                for tier in TIERS
            },
            "filtered": [
                {
                    "path": c["path"],
                    "line": c["start_line"],
                    "tools": c["tools"],
                    "filter_rules": c.get("filter_rules", []),
                }
                for c in unlabeled
                if c["disposition"] == "filtered"
            ],
        },
        "sources": report["sources"],
    }


def evaluate(labels, inputs):
    results = []
    for source in labels["sources"]:
        report_file = Path(inputs) / source["id"] / "report.json"
        if not report_file.is_file():
            # A source that could not be scanned stays in the table as a failure.
            results.append({"id": source["id"], "scan_status": "missing", "sites": []})
            continue
        results.append(score_source(source, json.loads(report_file.read_bytes())))
    sites = [site for result in results for site in result["sites"]]
    documented = sum(len(source["sites"]) for source in labels["sources"])
    summary = {
        "documented_sites": documented,
        "reported": sum(site["reported"] for site in sites),
        "in_first_tiers": sum(site["in_first_tiers"] for site in sites),
        "filtered": sum(site["filtered"] for site in sites),
        "missed": documented - sum(site["reported"] for site in sites),
    }
    return {"summary": summary, "sources": results}


def markdown(result):
    lines = [
        "| Source | Scan | Documented site | Reported | Tools | Priority | Filtered |",
        "|---|---|---|---|---|---|---|",
    ]
    for source in result["sources"]:
        for site in source["sites"] or [None]:
            if site is None:
                lines.append(f"| {source['id']} | {source['scan_status']} | — | — | — | — | — |")
                continue
            lines.append(
                f"| {source['id']} | {source['scan_status']} | `{site['path']}:{site['line']}` | "
                f"{'yes' if site['reported'] else 'no'} | {', '.join(site['tools']) or '—'} | "
                f"{site['priority'] or '—'} | {'yes' if site['filtered'] else 'no'} |"
            )
    lines += [
        "",
        "| Source | Candidates | Unlabeled | Unlabeled in main list (P1/P2/U/P3/P4) | Unlabeled filtered |",
        "|---|---:|---:|---|---:|",
    ]
    for source in result["sources"]:
        if "unlabeled" not in source:
            continue
        counts = source["unlabeled"]["main_list_by_priority"]
        lines.append(
            f"| {source['id']} | {source['stages']['candidates']} | {source['unlabeled']['total']} | "
            f"{' / '.join(str(counts[tier]) for tier in TIERS)} | "
            f"{len(source['unlabeled']['filtered'])} |"
        )
    summary = result["summary"]
    lines += [
        "",
        f"Documented sites: {summary['documented_sites']}; reported {summary['reported']}, "
        f"in P1/P2 {summary['in_first_tiers']}, filtered {summary['filtered']}, "
        f"missed {summary['missed']}.",
    ]
    return "\n".join(lines) + "\n"


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
