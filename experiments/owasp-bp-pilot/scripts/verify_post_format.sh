#!/usr/bin/env bash
# Check that the post-freeze formatting of the pilot scripts (FREEZE_DEVIATION.md) changed no
# measurement: generated queries, re-scoring of stored SARIF, the counterexample run and the
# BenchmarkPython CodeQL run (v0.1, v0.2) are compared with the stored results.
# Usage: verify_post_format.sh WORK_DIR   (Linux; CODEQL = pinned bundle; fetches BenchmarkPython)
set -euo pipefail
P=$(cd "$(dirname "$0")/.." && pwd); E=$P/..; A=$E/../artifacts/owasp-bp-pilot; W=$1; C=${CODEQL:-codeql}
BP_COMMIT=f1291485808b66e20ddb6b01b10dc71b3df8c8ba
rm -rf "$W"; mkdir -p "$W/score" "$W/bp"
cp -r "$P/ql" "$W/ql01"; cp -r "$P/ql_v02" "$W/ql02"; cp -r "$P/counterexamples" "$W/cex"
for v in 01 02; do (cd "$W/ql$v" && python3 -I gen.py > /dev/null && $C pack install > /dev/null 2>&1); done
cp "$P/ql_v02/table/Evidence.ql" "$W/ql02/table/Committed.ql"

echo "== 1. v0.2 queries (generated alert queries, committed table/Evidence.ql) vs wave-a/query_hashes.txt"
h() { sha256sum < "$1" | cut -d' ' -f1; }
(
  cd "$W/ql02"
  for f in SafetyEvidence.qll qlpack.yml queries/cwe{22,78,79,643}_{all,none}.ql; do echo "$(h $f)  q/${f#queries/}"; done
  echo "$(h table/Committed.ql)  qt/Evidence.ql"
) | sort -k2 > "$W/now.txt"
diff <(sort -k2 "$E/wave-a/query_hashes.txt") "$W/now.txt" && echo "same      all $(wc -l < "$W/now.txt") files"
echo "generated table/Evidence.ql: $(h "$W/ql02/table/Evidence.ql") (whitespace-only difference, see FREEZE_DEVIATION.md)"

echo "== 2. re-score stored inputs with the committed scripts"
cp "$P/split.json" "$P/semgrep_rules.json" "$A"/{semgrep.sarif,codeql.sarif,bandit.json,evidence.sarif,evidence_v02.sarif} "$W/score/"
python3 -I "$P/scripts/evaluate.py" "$W/score" development > /dev/null
for s in development test; do
  python3 -I "$P/scripts/evaluate_evidence.py" "$W/score" $s > /dev/null
  python3 -I "$P/scripts/evaluate_evidence.py" "$W/score" $s "$W/score/evidence_v02.sarif" _v02 > /dev/null
done
python3 -I - "$W/score" "$P" <<'EOF'
import json, sys
for f in ("pilot_development", "evidence_development", "evidence_test", "evidence_v02_development", "evidence_v02_test"):
    a, b = (json.load(open(f"{d}/{f}.json")) for d in sys.argv[1:])
    print("same     " if a == b else "DIFFERENT", f"{f}.json")
EOF

echo "== 3. counterexample run (v0.1, v0.2) vs cex_results.json"
$C database create "$W/cex_db" --language=python --source-root="$W/cex" -q > /dev/null 2>&1
for v in 01 02; do
  $C database analyze "$W/cex_db" "$W"/ql$v/queries/cwe{22,78,79,643}_{none,all}.ql \
    --format=sarif-latest --output="$W/v$v.sarif" --rerun -q > /dev/null 2>&1
done
python3 -I "$P/scripts/evaluate_cex.py" "$W/cex" "$W/v01.sarif" "$W/v02.sarif" > /dev/null
python3 -I - "$W/cex_results.json" "$P/cex_results.json" <<'EOF'
import json, sys
a, b = (json.load(open(p)) for p in sys.argv[1:])
for k in sorted(b):
    same = sorted(map(tuple, a[k]["rows"])) == sorted(map(tuple, b[k]["rows"]))
    print("same     " if same else "DIFFERENT", k, a[k]["counts"])
EOF

echo "== 4. BenchmarkPython CodeQL run (v0.1, v0.2) vs stored SARIF and evidence table"
git -C "$W/bp" init -q src && git -C "$W/bp/src" fetch -q --depth 1 https://github.com/OWASP-Benchmark/BenchmarkPython $BP_COMMIT
git -C "$W/bp/src" checkout -q FETCH_HEAD
$C database create "$W/bp/db" --language=python --source-root "$W/bp/src" -q > /dev/null 2>&1
$C database analyze "$W/bp/db" "$W/ql01/queries" --format=sarif-latest --output="$W/bp/evidence.sarif" --rerun -q > /dev/null 2>&1
$C database analyze "$W/bp/db" "$W/ql02/queries" --format=sarif-latest --output="$W/bp/evidence_v02.sarif" --rerun -q > /dev/null 2>&1
for q in Evidence Committed; do
  $C query run "$W/ql02/table/$q.ql" -d "$W/bp/db" -o "$W/bp/$q.bqrs" > /dev/null 2>&1
  $C bqrs decode "$W/bp/$q.bqrs" --format=csv -o "$W/bp/$q.csv"
done
python3 -I - "$W/bp" "$A" <<'EOF'
import collections, csv, json, sys
W, A = sys.argv[1:]
def res(p):
    return collections.Counter(
        (r["ruleId"], l["artifactLocation"]["uri"], l["region"]["startLine"], l["region"].get("startColumn"), r["message"]["text"])
        for r in json.load(open(p))["runs"][0]["results"] for l in [r["locations"][0]["physicalLocation"]])
for f in ("evidence.sarif", "evidence_v02.sarif"):
    a, b = res(f"{W}/{f}"), res(f"{A}/{f}")
    print("same     " if a == b else "DIFFERENT", f, sum(a.values()), "results")
rows = lambda p: sorted(map(tuple, csv.reader(open(p))))
g, c, s = rows(f"{W}/Evidence.csv"), rows(f"{W}/Committed.csv"), rows(f"{A}/evidence_table_v02.csv")
print("same     " if g == c == s else "DIFFERENT", "evidence_table_v02.csv (generated and committed Evidence.ql)", len(s), "rows")
EOF
