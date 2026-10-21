#!/usr/bin/env bash
# Counterexample runs for v0.3 (SPEC §8 criteria 1, 2, 5, 6; SPEC_RESOURCE.md §6). The expectation
# tables must match their lock before anything runs. Every run evaluates v0.3 in both modes:
# strict (st/cwe-22/v03, contracts of level "proved") and scoped (st/cwe-22/v03s, also resource
# contracts).
#   ipg suite: the ipg_* cases under the four contract scenarios (declared, none, wrong_root,
#     conflict); scoped must not change any of them.
#   resource suite: the res_* cases (same database), with the resources contract pack.
#   tmpdir suite (counterexamples_tmpdir): tempfile.tempdir set from request data.
#   pilot suite: frozen evaluate_cex.py with the declared contract.
# Usage: run_cex.sh WORK_DIR   (Linux; CODEQL = pinned bundle). Exit 1 on any failed check.
set -euo pipefail
H=$(cd "$(dirname "$0")/.." && pwd); P=$H/../owasp-bp-pilot; W=$1; C=${CODEQL:-codeql}; fail=0
XI=$H/expectations/ipg_expectations.csv; XR=$H/expectations/resources_expectations.csv
(cd "$H/expectations" && sha256sum -c --quiet EXPECTATIONS.sha256 2> /dev/null)
rm -rf "$W"; mkdir -p "$W/ipg" "$W/pilot" "$W/tmpdir"
cp -r "$P/ql_v02" "$W/ql02"; cp -r "$H/ql" "$W/ql03"; cp -r "$H/policy" "$H/policy_scenarios" "$W/"
cp -r "$H/counterexamples" "$W/ipg/cex"; cp -r "$P/counterexamples" "$W/pilot/cex"
cp -r "$H/counterexamples_tmpdir" "$W/tmpdir/cex"
(cd "$W/ql02" && python3 -I gen.py > /dev/null)
for x in "$XI" "$XR"; do python3 -I "$H/scripts/check_semantics.py" "$W/ipg/cex" "$x" | tail -1; done
AP=--additional-packs="$W/ql02:$W/ql03:$W/policy:$W/policy_scenarios"
(cd "$W/ql03" && $C pack install "$AP" > /dev/null 2>&1)
declare -A PACK=([declared]=security-triage/cex-sink-policy [none]=""
  [wrong_root]=security-triage/cex-sink-policy-wrong-root [conflict]=security-triage/cex-sink-policy-conflict
  [resources]=security-triage/cex-sink-policy-resources)
for s in ipg pilot tmpdir; do
  $C database create "$W/$s/db" --language=python --source-root="$W/$s/cex" -q > /dev/null 2>&1
  $C database analyze "$W/$s/db" "$W"/ql02/queries/cwe{22,78,79,643}_{none,all}.ql "$AP" \
    --format=sarif-latest --output="$W/$s/base.sarif" --rerun -q
done
v03() { # SUITE PACK_KEY: strict and scoped alerts, suppression table under that contract pack
  local mp=(); [ -n "${PACK[$2]}" ] && mp=(--model-packs="${PACK[$2]}")
  $C database analyze "$W/$1/db" "$W/ql03/queries/cwe22_v03.ql" "$W/ql03/queries/cwe22_v03s.ql" "$AP" "${mp[@]}" \
    --format=sarif-latest --output="$W/$1/v03_$2.sarif" --rerun -q
  $C query run "$W/ql03/queries/V03Evidence.ql" -d "$W/$1/db" -o "$W/$1/evidence_$2.bqrs" "$AP" "${mp[@]}" > /dev/null 2>&1
  $C bqrs decode "$W/$1/evidence_$2.bqrs" --format=csv -o "$W/$1/evidence_$2.csv"
}
score() { # TABLE SCENARIO SUITE PACK_KEY
  for variant in v03 v03s; do
    python3 -I "$H/scripts/evaluate_scenarios.py" "$1" "$2" $variant "$W/$3/cex" "$W/$3/base.sarif" "$W/$3/v03_$4.sarif" || fail=1
  done
  python3 -I "$H/scripts/subset_check.py" none,all,v03,v03s "$W/$3/base.sarif" "$W/$3/v03_$4.sarif" || fail=1
  cat "$W/$3/evidence_$4.csv"
}
for sc in declared none wrong_root conflict; do
  v03 ipg $sc; echo "#### ipg / $sc"; score "$XI" $sc ipg $sc
done
pair() { # SUITE PACK_KEY STRICT_SCENARIO SCOPED_SCENARIO: one table scenario per mode
  python3 -I "$H/scripts/evaluate_scenarios.py" "$XR" $3 v03 "$W/$1/cex" "$W/$1/base.sarif" "$W/$1/v03_$2.sarif" || fail=1
  python3 -I "$H/scripts/evaluate_scenarios.py" "$XR" $4 v03s "$W/$1/cex" "$W/$1/base.sarif" "$W/$1/v03_$2.sarif" || fail=1
  python3 -I "$H/scripts/subset_check.py" none,all,v03,v03s "$W/$1/base.sarif" "$W/$1/v03_$2.sarif" || fail=1
  cat "$W/$1/evidence_$2.csv"
}
v03 ipg resources; echo "#### resources"; pair ipg resources res_strict res_scoped
v03 tmpdir none; echo "#### tmpdir"; pair tmpdir none tmpdir_strict tmpdir_scoped
$C query run "$W/ql03/queries/V03Resources.ql" -d "$W/ipg/db" -o "$W/ipg/resources.bqrs" "$AP" > /dev/null 2>&1
$C bqrs decode "$W/ipg/resources.bqrs" --format=csv -o "$W/ipg/resources.csv" && cat "$W/ipg/resources.csv"
v03 pilot declared
# evaluate_cex.py (frozen with v0.2) compares `none` with `all`: v03.sarif replaces the CWE-22
# `all` results by v0.3 strict, v03s.sarif by v0.3 scoped (v0.3 changes CWE-22 only).
python3 -I - "$W/pilot" <<'EOF'
import json, sys
d = sys.argv[1]
base = json.load(open(f"{d}/base.sarif"))
v03 = json.load(open(f"{d}/v03_declared.sarif"))["runs"][0]["results"]
json.dump(base, open(f"{d}/v02.sarif", "w"))
keep = [r for r in base["runs"][0]["results"] if not r["ruleId"].endswith("cwe-22/all")]
for label in ("v03", "v03s"):
    rs = [dict(r, ruleId="st/cwe-22/all") for r in v03 if r["ruleId"].split("/")[-1] == label]
    base["runs"][0]["results"] = keep + rs
    json.dump(base, open(f"{d}/{label}.sarif", "w"))
EOF
echo "#### pilot / declared"
python3 -I "$P/scripts/evaluate_cex.py" "$W/pilot/cex" "$W/pilot/v02.sarif" "$W/pilot/v03.sarif" "$W/pilot/v03s.sarif"
python3 -I "$H/scripts/subset_check.py" none,all,v03,v03s "$W/pilot/base.sarif" "$W/pilot/v03_declared.sarif" || fail=1
cat "$W/pilot/evidence_declared.csv"
exit $fail
