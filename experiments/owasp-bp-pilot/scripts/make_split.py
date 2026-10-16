"""Deterministic dev/test split of BenchmarkPython 0.1 for the 4 study CWEs.
Stratified by (CWE, expected label); order by sha256(salt + test name);
first half -> development."""

import csv
import hashlib
import json
import math
import sys
from collections import Counter

SALT = "security-triage/owasp-bp-split-v1/"
CWES = {"22", "78", "79", "643"}
rows = [r for r in csv.reader(open(sys.argv[1])) if r and not r[0].startswith("#")]
strata = {}
for name, _category, real, cwe, *_ in rows:
    cwe = cwe.strip()
    if cwe in CWES:
        strata.setdefault((cwe, real.strip() == "true"), []).append(name.strip())
out = {
    "salt": SALT,
    "source": "expectedresults-0.1.csv @ f1291485808b66e20ddb6b01b10dc71b3df8c8ba",
    "cases": {},
}
for (cwe, real), names in sorted(strata.items()):
    names.sort(key=lambda n: hashlib.sha256((SALT + n).encode()).hexdigest())
    k = math.ceil(len(names) / 2)
    for i, n in enumerate(names):
        out["cases"][n] = {
            "cwe": int(cwe),
            "expected_vulnerable": real,
            "split": "development" if i < k else "test",
        }
json.dump(out, open(sys.argv[2], "w"), indent=1, sort_keys=True)

print(Counter((v["cwe"], v["expected_vulnerable"], v["split"]) for v in out["cases"].values()))
