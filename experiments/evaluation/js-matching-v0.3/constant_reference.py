"""Score filter rule G4 against reference labels that do not come from Semgrep.

For every JavaScript candidate of the v0.3 exports whose call is `child_process.exec` or
`execSync`, constant_reference.cjs decides from the package source whether the command string
is a constant (see that file for the rule). That verdict is the reference label of the one
class of false positive G4 is about:

- reference `constant_command`, pattern alerts only  -> a false positive of this class;
- G4 filtered it                                     -> filtered correctly;
- G4 filtered a call whose reference is not constant -> filtered wrongly.

The label says nothing about any other kind of false positive, and nothing about whether a
non-constant command is exploitable.

    python experiments/evaluation/js-matching-v0.3/constant_reference.py [--json OUT]

Needs Node.js and the network: each package is downloaded from npm, the files that hold a
candidate are written to a temporary folder and parsed there. Nothing is executed.
The saved output is results/constant-reference.json.
"""

import argparse
import io
import json
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
SHELL_STRING = {"child_process.exec", "child_process.execSync"}
# Tools whose alert claims a data flow to the command. A pattern alert (ESLint, a Semgrep
# audit rule) does not.
FLOW_RULE_PREFIXES = ("js/",)
FLOW_SEMGREP_RULES = ("detect-child-process", "shelljs-exec-injection")


def candidate_rows(source):
    folder = HERE / "inputs" / source["id"]
    report = json.loads((folder / "report.json").read_bytes())
    sarif = json.loads((folder / "report.sarif").read_bytes())
    rules = {}
    for run in sarif["runs"]:
        for result in run["results"]:
            key = result["properties"]["securityTriage"]["candidateKey"]
            rules.setdefault(key, set()).add(result["ruleId"])
    rows = []
    for candidate in report["candidates"]:
        if candidate["sink_kind"] not in SHELL_STRING or candidate["basis"] != "same_call_site":
            continue
        alert_rules = sorted(rules.get(candidate["candidate_key"], ()))
        flow = any(
            rule.startswith(FLOW_RULE_PREFIXES) or rule.rsplit(".", 1)[-1] in FLOW_SEMGREP_RULES
            for rule in alert_rules
        )
        rows.append(
            {
                "id": source["id"],
                "path": candidate["path"],
                "line": candidate["start_line"],
                "tools": candidate["tools"],
                "rules": alert_rules,
                "flow_claim": flow,
                "disposition": candidate["disposition"],
                "filter_rules": candidate.get("filter_rules") or [],
            }
        )
    return rows


def reference(source, rows, sinks):
    """Attach the reference verdict to each row of one package."""
    package = f"{source['package']}@{source['version']}"
    spans = {}
    for sink in sinks.get(package, []):
        spans.setdefault((sink["path"], sink["start"][0]), (sink["start"][1], *sink["end"]))
    url = f"https://registry.npmjs.org/{source['package']}/{source['version']}"
    with urllib.request.urlopen(url, timeout=60) as response:
        tarball = json.load(response)["dist"]["tarball"]
    with urllib.request.urlopen(tarball, timeout=120) as response:
        data = response.read()
    by_file = {}
    for row in rows:
        by_file.setdefault(row["path"], []).append(row)
    with (
        tempfile.TemporaryDirectory() as folder,
        tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive,
    ):
        for index, (path, members) in enumerate(sorted(by_file.items())):
            try:
                text = archive.extractfile("package/" + path).read()
            except (KeyError, AttributeError):
                for row in members:
                    row.update(reference="unreadable", command=None)
                continue
            target = Path(folder) / f"{index}.js"
            target.write_bytes(text)
            calls = []
            for row in members:
                column, end_line, end_column = spans.get((path, row["line"]), (None, None, None))
                calls.append(
                    {
                        "line": row["line"],
                        "column": column,
                        "endLine": end_line,
                        "endColumn": end_column,
                    }
                )
            done = subprocess.run(
                ["node", str(HERE / "constant_reference.cjs")],
                input=json.dumps({"file": str(target), "calls": calls}),
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=False,
            )
            verdicts = json.loads(done.stdout) if done.returncode == 0 else []
            for position, row in enumerate(members):
                verdict = verdicts[position] if position < len(verdicts) else {}
                row.update(
                    reference=verdict.get("verdict", "unreadable"), command=verdict.get("command")
                )
    return rows


def evaluate():
    listed = json.loads((HERE / "sources.json").read_bytes())
    sinks = json.loads((HERE / "v1-sinks.json").read_bytes())["sinks"]
    rows = []
    for source in listed["sources"]:
        found = candidate_rows(source)
        if found:
            rows += reference(source, found, sinks)
    return summarize(rows)


def summarize(rows):
    def count(predicate):
        return sum(1 for row in rows if predicate(row))

    constant = [row for row in rows if row["reference"] == "constant_command"]
    filtered = [row for row in rows if row["disposition"] == "filtered"]
    return {
        "note": (
            "Reference labels for one class of false positive only: a shell-string call whose "
            "command is a constant. Development data."
        ),
        "shell_string_candidates": len(rows),
        "reference": {
            verdict: count(lambda row, verdict=verdict: row["reference"] == verdict)
            for verdict in ("constant_command", "not_constant", "unreadable")
        },
        "constant_by_reference": {
            "pattern_alerts_only": count(
                lambda row: row["reference"] == "constant_command" and not row["flow_claim"]
            ),
            "with_a_flow_claim": count(
                lambda row: row["reference"] == "constant_command" and row["flow_claim"]
            ),
        },
        "g4": {
            "filtered": len(filtered),
            "filtered_and_constant_by_reference": count(
                lambda row: (
                    row["disposition"] == "filtered" and row["reference"] == "constant_command"
                )
            ),
            "filtered_but_not_constant_by_reference": count(
                lambda row: (
                    row["disposition"] == "filtered" and row["reference"] != "constant_command"
                )
            ),
            "constant_pattern_only_but_kept": count(
                lambda row: (
                    row["reference"] == "constant_command"
                    and not row["flow_claim"]
                    and row["disposition"] != "filtered"
                )
            ),
        },
        "constant_candidates": constant,
        "candidates": rows,
    }


def markdown(result):
    lines = [
        f"Shell-string candidates: {result['shell_string_candidates']}; reference: "
        f"{result['reference']}.",
        f"Constant by reference: {result['constant_by_reference']}.",
        f"G4: {result['g4']}.",
    ]
    for row in result["constant_candidates"]:
        lines.append(
            f"  constant: {row['id']} {row['path']}:{row['line']} {row['tools']} "
            f"flow={row['flow_claim']} {row['disposition']} | {row['command']}"
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
