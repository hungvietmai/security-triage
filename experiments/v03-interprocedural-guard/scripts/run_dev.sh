#!/usr/bin/env bash
# v0.3 strict and scoped on real code without any declared contract (SPEC §8 criteria 3, 4, 5;
# SPEC_RESOURCE.md §6): the wave B
# development versions (mlflow, Django; fixed side of the locked pairs) and BenchmarkPython.
# Reports, per CWE-22 alert of v0.2: allowed root found or not, containment proven or not,
# suppressed or not, and the wave B label. Also compares the default / v0.2 CWE-22 results with
# the wave B SARIF kept in artifacts/wave-b/wave-b-raw.tar.gz (query identity for these versions).
# Usage: run_dev.sh WORK_DIR   (Linux; CODEQL = pinned bundle; fetches the three repositories)
set -euo pipefail
H=$(cd "$(dirname "$0")/.." && pwd); P=$H/../owasp-bp-pilot; E=$H/..; A=$E/../artifacts
W=$1; C=${CODEQL:-codeql}; fail=0
rm -rf "$W"; mkdir -p "$W"
cp -r "$P/ql_v02" "$W/ql02"; cp -r "$H/ql" "$W/ql03"
(cd "$W/ql02" && python3 -I gen.py > /dev/null)
AP=--additional-packs="$W/ql02:$W/ql03"
(cd "$W/ql03" && $C pack install "$AP" > /dev/null 2>&1)
scan() { # NAME REPOSITORY COMMIT [WAVE_B_VERSION]
  local d=$W/$1
  mkdir -p "$d"
  git -C "$d" init -q src && git -C "$d/src" fetch -q --depth 1 "https://github.com/$2" "$3"
  git -C "$d/src" checkout -q FETCH_HEAD
  echo "$1 $(git -C "$d/src" rev-parse HEAD)"
  $C database create "$d/db" --language=python --source-root "$d/src" --ram=5000 -q > /dev/null 2>&1
  $C database analyze "$d/db" "$W/ql02/queries/cwe22_none.ql" "$W/ql02/queries/cwe22_all.ql" \
    "$W/ql03/queries/cwe22_v03.ql" "$W/ql03/queries/cwe22_v03s.ql" "$AP" --format=sarif-latest \
    --output="$d/all.sarif" --rerun --ram=5000 -q
  for q in V03Contracts V03Evidence V03Summaries V03Resources; do
    $C query run "$W/ql03/queries/$q.ql" -d "$d/db" -o "$d/$q.bqrs" "$AP" --ram=5000 > /dev/null 2>&1
    $C bqrs decode "$d/$q.bqrs" --format=csv -o "$d/$q.csv"
  done
  python3 -I "$H/scripts/subset_check.py" none,all,v03,v03s "$d/all.sarif" || fail=1
  if [ -n "${4:-}" ]; then
    tar -xzOf "$A/wave-b/wave-b-raw.tar.gz" "wave-b-raw/$4/v02.sarif" > "$d/wave_b_v02.sarif"
  fi
}
scan mlflow mlflow/mlflow 6e801f4259d96804c73107315b24cef0f6aa115a GHSA-42h5-h8qh-vv9v__fixed
scan django django/django 05413afa8c18cdb978fcdf470e09f7a12b234a23 GHSA-fvgf-6h6h-3322__fixed
scan bp OWASP-Benchmark/BenchmarkPython f1291485808b66e20ddb6b01b10dc71b3df8c8ba
python3 -I "$H/scripts/contract_report.py" "$W" "$E/wave-b/results/wave_b_labels.csv" > "$W/report.txt" || fail=1
cat "$W/report.txt"
# BenchmarkPython scoring (criterion 4): the stored v0.2 SARIF (identical to a rerun, see
# ../owasp-bp-pilot/FREEZE_DEVIATION.md) with its CWE-22 `all` results replaced by v0.3 strict / scoped.
mkdir -p "$W/bp/score"
cp "$P/split.json" "$P/semgrep_rules.json" "$A/owasp-bp-pilot/semgrep.sarif" "$W/bp/score/"
for v in v03 v03s; do
  python3 -I - "$A/owasp-bp-pilot/evidence_v02.sarif" "$W/bp/all.sarif" "$W/bp/score/evidence_$v.sarif" $v <<'EOF'
import json, sys
base = json.load(open(sys.argv[1]))
new = [r for r in json.load(open(sys.argv[2]))["runs"][0]["results"] if r["ruleId"] == "st/cwe-22/" + sys.argv[4]]
for r in new:
    r["ruleId"] = "st/cwe-22/all"
base["runs"][0]["results"] = [r for r in base["runs"][0]["results"] if r["ruleId"] != "st/cwe-22/all"] + new
json.dump(base, open(sys.argv[3], "w"))
EOF
  for s in development test; do
    python3 -I "$P/scripts/evaluate_evidence.py" "$W/bp/score" $s "$W/bp/score/evidence_$v.sarif" "_$v" > /dev/null
    python3 -I - "$W/bp/score/evidence_${v}_$s.json" "$P/evidence_v02_$s.json" "$s $v" <<'EOF' || fail=1
import json, sys
new, v02 = (json.load(open(p)) for p in sys.argv[1:3])
e = lambda r: {k: r["per_cwe"]["22"]["E_codeql_evidence"][k] for k in ("TP", "FP", "FN", "TN")}
lost = new["attribution"]["22"]["all"]["TP_lost"]
print(f"BenchmarkPython {sys.argv[3]} CWE-22: v0.2 {e(v02)}  v0.3 {e(new)}  TP lost vs default: {lost}")
sys.exit(1 if lost or e(new)["TP"] != e(v02)["TP"] else 0)
EOF
  done
done
exit $fail
