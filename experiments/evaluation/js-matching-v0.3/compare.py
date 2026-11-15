"""Before/after comparison of JavaScript matching: saved v0.2 exports against v0.3 rescans.

For every source of sources.json it reads the saved v0.2 export and the v0.3 export and reports

- candidates and unmatched candidates (basis `unmatched_location`, queue U) before and after;
- for each alert that was unmatched before: merged into a located call after, still unmatched,
  or no longer reported;
- a wrong-merge check for every newly merged alert: its primary region, or one of its related
  locations, must lie inside the span of the call the candidate starts on. Call spans come from
  v1-sinks.json, the v1 locator's own output for the same package (see README.md);
- known vulnerable sites (labels of the second independent check and of the pairs-v1
  development split) reported before and after, and whether filtering removed one;
- candidates filtered after, with their rule.

Sources whose code was read to design the fix (`used_to_fix`) are reported apart from the rest.
Nothing here has a safe label, so no number below is a false-positive reduction.

    python experiments/evaluation/js-matching-v0.3/compare.py [--json OUT]
"""

import argparse
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
EVALUATION = HERE.parent
JS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")


def known_sites():
    """{package@version: [(path, line)]} from the two label files with published locations."""
    sites = {}
    files = (
        EVALUATION / "independent-secbench" / "labels.json",
        EVALUATION / "pairs-v1" / "development" / "labels.json",
    )
    for file in files:
        for source in json.loads(file.read_bytes())["sources"]:
            if source.get("kind") != "npm":
                continue
            key = f"{source['package']}@{source['version']}"
            for site in source["sites"]:
                if (site["path"], site["line"]) not in sites.setdefault(key, []):
                    sites[key].append((site["path"], site["line"]))
    return sites


def alerts(folder):
    """Every exported alert with the candidate it belongs to."""
    report = json.loads((folder / "report.json").read_bytes())
    candidates = {c["candidate_key"]: c for c in report["candidates"]}
    rows = []
    sarif = json.loads((folder / "report.sarif").read_bytes())
    for run in sarif["runs"]:
        tool = run["tool"]["driver"]["name"]
        for result in run["results"]:
            location = result["locations"][0]["physicalLocation"]
            path = location["artifactLocation"]["uri"]
            if not path.endswith(JS):
                continue
            region = location.get("region", {})
            related = [
                (
                    other["physicalLocation"]["artifactLocation"]["uri"],
                    other["physicalLocation"].get("region", {}),
                )
                for other in result.get("relatedLocations", [])
                if "physicalLocation" in other
            ]
            candidate = candidates[result["properties"]["securityTriage"]["candidateKey"]]
            identity = (
                tool,
                result["ruleId"],
                path,
                region.get("startLine"),
                region.get("startColumn"),
                region.get("endLine", region.get("startLine")),
                region.get("endColumn"),
            )
            rows.append(
                {"id": identity, "region": region, "related": related, "candidate": candidate}
            )
    return report, rows


def inside(region, sink):
    start = (region.get("startLine"), region.get("startColumn", 1))
    end = (region.get("endLine", region.get("startLine")), region.get("endColumn", 10**6))
    return tuple(sink["start"]) <= start and end <= tuple(sink["end"])


def consistent(alert, sinks):
    """Does the alert point into the call its candidate starts on?"""
    candidate = alert["candidate"]
    calls = [
        sink
        for sink in sinks
        if sink["path"] == candidate["path"] and sink["start"][0] == candidate["start_line"]
    ]
    if any(inside(alert["region"], call) for call in calls):
        return True
    return any(
        path == call["path"] and region and inside(region, call)
        for path, region in alert["related"]
        for call in calls
    )


def compare_source(source, sites, sinks):
    before_folder = EVALUATION / source["before"][0]["export"]
    after_folder = HERE / "inputs" / source["id"]
    row = {
        "id": source["id"],
        "used_to_fix": source["used_to_fix"],
        "before_status": source["before"][0]["scan_status"],
    }
    if not (after_folder / "report.json").is_file():
        return {**row, "after_status": "missing"}
    before_report, before = alerts(before_folder)
    after_report, after = alerts(after_folder)
    row["after_status"] = after_report["status"]

    def js_candidates(report):
        return [c for c in report["candidates"] if (c["path"] or "").endswith(JS)]

    def unmatched(report):
        return [c for c in js_candidates(report) if c["basis"] != "same_call_site"]

    row["candidates"] = [len(js_candidates(before_report)), len(js_candidates(after_report))]
    row["unmatched_candidates"] = [len(unmatched(before_report)), len(unmatched(after_report))]
    after_by_id = {alert["id"]: alert for alert in after}
    moved = {"merged": 0, "still_unmatched": 0, "not_reported_after": 0}
    wrong = []
    for alert in before:
        if alert["candidate"]["basis"] == "same_call_site":
            continue
        now = after_by_id.get(alert["id"])
        if now is None:
            moved["not_reported_after"] += 1
        elif now["candidate"]["basis"] != "same_call_site":
            moved["still_unmatched"] += 1
        else:
            moved["merged"] += 1
            if not consistent(now, sinks):
                wrong.append(list(alert["id"]))
    row["alerts_unmatched_before"] = moved
    row["newly_merged_not_inside_the_call"] = wrong
    # The opposite direction must stay empty: an alert merged before and unmatched now.
    before_by_id = {alert["id"]: alert for alert in before}
    row["alerts_that_lost_their_call"] = [
        list(alert["id"])
        for alert in after
        if alert["candidate"]["basis"] != "same_call_site"
        and alert["id"] in before_by_id
        and before_by_id[alert["id"]]["candidate"]["basis"] == "same_call_site"
    ]
    row["sites"] = []
    for path, line in sites:

        def at(report, path=path, line=line):
            found = [
                c for c in report["candidates"] if c["path"] == path and c["start_line"] == line
            ]
            return {
                "reported": bool(found),
                "tools": sorted({tool for c in found for tool in c["tools"]}),
                "filtered": bool(found) and all(c["disposition"] == "filtered" for c in found),
            }

        row["sites"].append(
            {"path": path, "line": line, "before": at(before_report), "after": at(after_report)}
        )
    row["filtered_after"] = [
        {
            "path": c["path"],
            "line": c["start_line"],
            "tools": c["tools"],
            "rules": c.get("filter_rules") or [],
        }
        for c in after_report["candidates"]
        if c["disposition"] == "filtered"
    ]
    row["filtered_before"] = sum(
        1 for c in before_report["candidates"] if c["disposition"] == "filtered"
    )
    return row


def summarize(rows):
    done = [row for row in rows if row.get("after_status") not in {"missing", "failed"}]
    total = {
        "sources": len(rows),
        "compared": len(done),
        "after_status": {},
        "candidates": [0, 0],
        "unmatched_candidates": [0, 0],
        "alerts_unmatched_before": {"merged": 0, "still_unmatched": 0, "not_reported_after": 0},
        "newly_merged_not_inside_the_call": 0,
        "alerts_that_lost_their_call": 0,
        "known_sites": {"total": 0, "reported_before": 0, "reported_after": 0, "filtered_after": 0},
        "filtered_after": 0,
    }
    for row in rows:
        status = row.get("after_status")
        total["after_status"][status] = total["after_status"].get(status, 0) + 1
    for row in done:
        for key in ("candidates", "unmatched_candidates"):
            total[key][0] += row[key][0]
            total[key][1] += row[key][1]
        for key, value in row["alerts_unmatched_before"].items():
            total["alerts_unmatched_before"][key] += value
        total["newly_merged_not_inside_the_call"] += len(row["newly_merged_not_inside_the_call"])
        total["alerts_that_lost_their_call"] += len(row["alerts_that_lost_their_call"])
        total["filtered_after"] += len(row["filtered_after"])
        for site in row["sites"]:
            total["known_sites"]["total"] += 1
            total["known_sites"]["reported_before"] += site["before"]["reported"]
            total["known_sites"]["reported_after"] += site["after"]["reported"]
            total["known_sites"]["filtered_after"] += site["after"]["filtered"]
    return total


def evaluate():
    listed = json.loads((HERE / "sources.json").read_bytes())
    sites = known_sites()
    spans = json.loads((HERE / "v1-sinks.json").read_bytes())["sinks"]
    rows = []
    for source in listed["sources"]:
        key = f"{source['package']}@{source['version']}"
        rows.append(compare_source(source, sites.get(key, []), spans.get(key, [])))
    return {
        "note": (
            "Development data. 'used_to_fix' sources were read to design the change; the other "
            "sources were scanned before but their code was not read."
        ),
        "used_to_fix": summarize([row for row in rows if row["used_to_fix"]]),
        "not_read": summarize([row for row in rows if not row["used_to_fix"]]),
        "all": summarize(rows),
        "sources": rows,
    }


def markdown(result):
    lines = ["| Measure | Read to design the fix | Not read | All |", "|---|---:|---:|---:|"]
    groups = [result["used_to_fix"], result["not_read"], result["all"]]

    def line(label, value):
        lines.append(f"| {label} | " + " | ".join(str(value(group)) for group in groups) + " |")

    line("Sources (compared)", lambda g: f"{g['sources']} ({g['compared']})")
    line("JavaScript candidates, before → after", lambda g: "{} → {}".format(*g["candidates"]))
    line(
        "Unmatched candidates (U), before → after",
        lambda g: "{} → {}".format(*g["unmatched_candidates"]),
    )
    line(
        "Alerts unmatched before: merged into a call after",
        lambda g: g["alerts_unmatched_before"]["merged"],
    )
    line(
        "Alerts unmatched before: still unmatched",
        lambda g: g["alerts_unmatched_before"]["still_unmatched"],
    )
    line(
        "Alerts unmatched before: not reported after",
        lambda g: g["alerts_unmatched_before"]["not_reported_after"],
    )
    line(
        "Newly merged alerts not inside the call (wrong merges)",
        lambda g: g["newly_merged_not_inside_the_call"],
    )
    line("Alerts merged before and unmatched after", lambda g: g["alerts_that_lost_their_call"])
    line("Known vulnerable sites", lambda g: g["known_sites"]["total"])
    line(
        "Known sites reported, before → after",
        lambda g: f"{g['known_sites']['reported_before']} → {g['known_sites']['reported_after']}",
    )
    line("Known sites filtered after", lambda g: g["known_sites"]["filtered_after"])
    line("Candidates filtered after", lambda g: g["filtered_after"])
    lines.append("")
    lines.append(f"Scan status after: {result['all']['after_status']}")
    for row in result["sources"]:
        for item in row.get("filtered_after", []):
            lines.append(
                f"filtered: {row['id']} {item['path']}:{item['line']} "
                f"{item['tools']} {item['rules']}"
            )
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv)
    result = evaluate()
    if args.json:
        args.json.write_bytes((json.dumps(result, indent=2, ensure_ascii=False) + "\n").encode())
    print(markdown(result), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
