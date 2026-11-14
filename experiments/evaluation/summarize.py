"""One table over several saved scan reports: stage counts and each tool's contribution.

Used where labels are missing or too few to score: it shows how many alerts each detection
tool contributed, how far merging reduced them and what filtering moved out of the main list.

    python experiments/evaluation/summarize.py <inputs-dir> [--json OUT]
"""

import argparse
import json
from pathlib import Path

TOOLS = ("semgrep", "codeql", "bandit", "eslint")
STAGES = ("raw_alerts", "units", "candidates", "main_list", "filtered", "demoted")


def summarize(inputs):
    rows = []
    for folder in sorted(path for path in Path(inputs).iterdir() if path.is_dir()):
        report = json.loads((folder / "report.json").read_bytes())
        rows.append(
            {
                "input": folder.name,
                "source": report["snapshot"]["source_coordinate"],
                "profile": report["profile"],
                "scan_status": report["status"],
                "stages": {name: report["stages"][name] for name in STAGES},
                "sources": report["sources"],
                "filtered_by_rule": report["filtered_by_rule"],
                "main_list_by_priority": report["main_list_by_priority"],
            }
        )
    return rows


def markdown(rows):
    head = ["Source", "Profile", "Status", *STAGES]
    head += [f"{tool} (only)" for tool in TOOLS]
    lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for row in rows:
        cells = [row["source"], row["profile"], row["scan_status"]]
        cells += [str(row["stages"][name]) for name in STAGES]
        for tool in TOOLS:
            source = row["sources"].get(tool)
            cells.append(f"{source['candidates']} ({source['only']})" if source else "—")
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("inputs", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv)
    rows = summarize(args.inputs)
    if args.json:
        args.json.write_bytes((json.dumps(rows, indent=2, ensure_ascii=False) + "\n").encode())
    print(markdown(rows), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
