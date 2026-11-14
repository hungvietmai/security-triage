"""Post-hoc reading of the documented sites the main rule counts as not reported.

WRITTEN AFTER THE RESULTS WERE KNOWN. It changes no number of configurations.py. For every
documented site that has no candidate starting on its line, it looks into the merged SARIF the
application exported and tells apart:

- `raw_alert_on_line`: a tool did report the published line, but the alert was not merged into
  a located call (it sits in a candidate without a call site, usually queue U);
- `related_location_on_line`: an alert reported elsewhere in the file names the published line
  as a related location (CodeQL does this for the shell command of a library-input alert);
- `raw_alert_in_file`: tools reported other lines of the file only;
- `no_alert_in_file`: no tool reported anything in that file;
- `not_scanned`: the scan failed, so there is no export to read.

    python experiments/evaluation/independent-secbench/posthoc_missed.py \
        <labels.json> <inputs-dir> <configurations.json> [--json OUT]
"""

import argparse
import json
from pathlib import Path


def raw_alerts(sarif):
    """Primary and related locations of every result in the merged SARIF log."""
    for run in sarif.get("runs", []):
        tool = run.get("tool", {}).get("driver", {}).get("name", "?")
        for result in run.get("results", []):
            places = [(loc, False) for loc in result.get("locations", [])]
            places += [(loc, True) for loc in result.get("relatedLocations", [])]
            for location, related in places:
                physical = location.get("physicalLocation", {})
                region = physical.get("region", {})
                start = region.get("startLine")
                yield {
                    "tool": (result.get("properties") or {}).get("tool", tool),
                    "rule": result.get("ruleId"),
                    "path": physical.get("artifactLocation", {}).get("uri"),
                    "start_line": start,
                    "end_line": region.get("endLine", start),
                    "related": related,
                }


def classify(site, alerts):
    in_file = [a for a in alerts if a["path"] == site["path"] and a["start_line"] is not None]
    on_line = [a for a in in_file if a["start_line"] <= site["line"] <= a["end_line"]]
    primary = [a for a in on_line if not a["related"]]
    if primary:
        return "raw_alert_on_line", sorted({a["tool"] for a in primary})
    if on_line:
        return "related_location_on_line", sorted({a["tool"] for a in on_line})
    if in_file:
        return "raw_alert_in_file", sorted({a["tool"] for a in in_file})
    return "no_alert_in_file", []


def read(result, inputs):
    rows = []
    for source in result["sources"]:
        for site in source["sites"]:
            if site["reported"]:
                continue
            row = {
                "id": source["id"],
                "scan_status": source["scan_status"],
                "path": site["path"],
                "line": site["line"],
            }
            sarif_file = Path(inputs) / source["id"] / "report.sarif"
            if source["scan_status"] == "failed" or not sarif_file.is_file():
                rows.append({**row, "reading": "not_scanned", "tools": []})
                continue
            alerts = list(raw_alerts(json.loads(sarif_file.read_bytes())))
            reading, tools = classify(site, alerts)
            rows.append({**row, "reading": reading, "tools": tools})
    counts = {}
    for row in rows:
        counts[row["reading"]] = counts.get(row["reading"], 0) + 1
    return {
        "note": "Post-hoc reading, written after the results were known; not a scored result.",
        "not_reported_sites": len(rows),
        "by_reading": counts,
        "sites": rows,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("labels", type=Path)
    parser.add_argument("inputs", type=Path)
    parser.add_argument("result", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv)
    reading = read(json.loads(args.result.read_bytes()), args.inputs)
    if args.json:
        args.json.write_bytes((json.dumps(reading, indent=2, ensure_ascii=False) + "\n").encode())
    print(reading["by_reading"])
    for row in reading["sites"]:
        print(
            f"{row['id']:38} {row['scan_status']:10} {row['path']}:{row['line']}  "
            f"{row['reading']} {','.join(row['tools'])}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
