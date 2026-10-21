"""Check that retained alert sets shrink along a chain of variants (SPEC §8, criterion 5).

R(variant) = set of (CWE, file, line, column) of the sink, read from the rule id
`st/cwe-<n>/<variant>`. For a chain `none,all` it checks R(all) ⊆ R(none); for
`none,all,v03` also R(v03) ⊆ R(all). Results of every given SARIF are merged.
Usage: subset_check.py VARIANT,VARIANT[,...] SARIF [SARIF ...]
"""

import itertools
import json
import sys

chain = sys.argv[1].split(",")
R = {v: set() for v in chain}
for path in sys.argv[2:]:
    with open(path) as f:
        results = json.load(f)["runs"][0]["results"]
    for r in results:
        _, cwe, variant = r["ruleId"].split("/")
        loc = r["locations"][0]["physicalLocation"]
        if variant in R:
            R[variant].add(
                (
                    cwe,
                    loc["artifactLocation"]["uri"],
                    loc["region"]["startLine"],
                    loc["region"].get("startColumn"),
                )
            )
fail = 0
for big, small in itertools.pairwise(chain):
    extra = sorted(R[small] - R[big])
    fail += len(extra)
    status = "FAIL" if extra else "ok"
    print(f"R({small}) ⊆ R({big}): {status}  |{small}|={len(R[small])} |{big}|={len(R[big])}")
    for e in extra:
        print("  only in", small, e)
sys.exit(1 if fail else 0)
