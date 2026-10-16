"""Review aid: tag the propagation idioms of each development case with simple regexes and
cross-tabulate them against the expected label and the tool cells. Not a detector; patterns are
BenchmarkPython generator idioms read from the source, used only to explain why alerts are wrong."""

import collections
import json
import re
import sys

OUT, SRC = sys.argv[1], sys.argv[2]
rep = json.load(open(f"{OUT}/pilot_development.json"))
PAT = {
    "const_arith_branch": r"7 \* \d+ [-+] num > 200",
    "const_string_branch": r"TestParam",
    "list_pop_index": r"lst\.pop\(0\)",
    "dict_lookup": r"map\d*\[|\.get\(['\"]key",
    "switch_on_const": r"guess|switch|match ",
    "guard_dotdot": r"'\.\./' in bar",
    "guard_resolve_prefix": r"startswith\(str\(testfiles\)\)",
    "escape_call": r"escape|quote\(|shlex",
    "helper_call": r"helpers\.ThingFactory|separate_request|\.doSomething",
}
rows = []
for cwe, lists in rep["lists"].items():
    for cell, cases in lists.items():
        for c in cases:
            src = open(f"{SRC}/testcode/{c}.py").read()
            body = src[src.find(f"def {c}_post") :]
            tags = [k for k, p in PAT.items() if re.search(p, body)]
            if "list_pop_index" in tags:
                m = re.search(r"bar = lst\[(\d)\]", body)
                tags.append(f"lst[{m.group(1)}]" if m else "lst[?]")
            rows.append(dict(case=c, cwe=cwe, cell=cell, tags=tags))
json.dump(rows, open(f"{OUT}/mechanisms_development.json", "w"), indent=1)
for scope in [
    "codeql_only/safe",
    "both/safe",
    "semgrep_only/safe",
    "codeql_only/true",
    "neither/true",
]:
    sel = [r for r in rows if r["cell"] == scope]
    cnt = collections.Counter(t for r in sel for t in r["tags"])
    none = sum(1 for r in sel if not r["tags"])
    print(f"{scope} n={len(sel)} untagged={none}", dict(cnt.most_common()))
