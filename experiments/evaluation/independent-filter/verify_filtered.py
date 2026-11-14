"""Check each filtered call against the source, with a rule fixed before the scans.

For a call the application filtered because "the whole command is a constant" (rule G2), this
script decides independently of the application whether that is true: it parses the file with
the standard-library parser and looks at the command argument of the call on that line. The
argument is constant when it is a string literal, a concatenation of string literals, or a
list or tuple of such. A name, an attribute, a call, an f-string with a placeholder or a
`%`/`.format` expression is not constant.

- `constant_command`: the filter was right; a constant command cannot be injected.
- `not_constant`: the filter was wrong.
- `unreadable`: the file or the call could not be read or parsed; no verdict.

The source lines are printed so that candidates filtered by other rules can be read by hand.
The file is fetched as text from the pinned commit and never executed.

    python experiments/evaluation/independent-filter/verify_filtered.py \
        <filtered-candidates.json> [--json OUT]
"""

import argparse
import ast
import json
import urllib.request
from pathlib import Path

COMMAND_KEYWORDS = ("args", "cmd", "command")


def is_constant(node):
    """True when the expression is built from string literals only."""
    if isinstance(node, ast.Constant):
        return isinstance(node.value, (str, bytes))
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return is_constant(node.left) and is_constant(node.right)
    if isinstance(node, ast.JoinedStr):
        return all(isinstance(part, ast.Constant) for part in node.values)
    if isinstance(node, (ast.List, ast.Tuple)):
        return bool(node.elts) and all(is_constant(item) for item in node.elts)
    return False


def command_argument(call):
    if call.args:
        return call.args[0]
    for keyword in call.keywords:
        if keyword.arg in COMMAND_KEYWORDS:
            return keyword.value
    return None


def verdict(source, line):
    """Verdict for the calls that start on `line`, and the text of the command argument."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return "unreadable", None
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and n.lineno == line]
    arguments = [a for a in (command_argument(call) for call in calls) if a is not None]
    if not arguments:
        return "unreadable", None
    # Several calls can start on one line (`f(g(x))`): every one must have a constant command.
    constant = all(is_constant(argument) for argument in arguments)
    text = " ; ".join(ast.unparse(argument) for argument in arguments)
    return ("constant_command" if constant else "not_constant"), text


def fetch(item):
    url = (
        f"https://raw.githubusercontent.com/{item['owner']}/{item['repo']}/"
        f"{item['commit']}/{item['path']}"
    )
    request = urllib.request.Request(url, headers={"User-Agent": "source-line-reader"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read().decode("utf-8", "replace")


def verify(result, fetch_fn=fetch):
    rows = []
    for item in result["filtered"]:
        try:
            source = fetch_fn(item)
        except Exception as error:  # noqa: BLE001 - a source that cannot be read has no verdict
            rows.append({**item, "verdict": "unreadable", "command": None, "lines": [str(error)]})
            continue
        outcome, command = verdict(source, item["line"]) if item["line"] else ("unreadable", None)
        lines = source.splitlines()
        first = max(1, (item["line"] or 1) - 3)
        shown = [f"{n}: {lines[n - 1]}" for n in range(first, min(len(lines), first + 6) + 1)]
        rows.append({**item, "verdict": outcome, "command": command, "lines": shown})
    counts = {}
    for row in rows:
        counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1
    return {"verdicts": counts, "filtered": rows}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("result", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv)
    checked = verify(json.loads(args.result.read_bytes()))
    if args.json:
        args.json.write_bytes((json.dumps(checked, indent=2, ensure_ascii=False) + "\n").encode())
    print(checked["verdicts"])
    for row in checked["filtered"]:
        print(f"\n{row['id']} {row['path']}:{row['line']}  {row['filter_rules']}  {row['verdict']}")
        print(f"   command: {row['command']}")
        for line in row["lines"]:
            print("   " + line[:150])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
