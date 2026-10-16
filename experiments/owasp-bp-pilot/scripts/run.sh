#!/usr/bin/env bash
# Reproduce the BenchmarkPython pilot. Requires semgrep 1.178.0, bandit 1.9.4, CodeQL bundle 2.27.1
# (codeql-bundle-python-linux64.tar.zst, sha256 ea86393c…0cb0, python-queries 1.8.11).
# BP = BenchmarkPython checkout at f1291485808b66e20ddb6b01b10dc71b3df8c8ba
# RULES = semgrep/semgrep-rules checkout at a84ff9cc2453ca91d581380de4b8b3f272f6f4be
set -euo pipefail
BP=${BP:?}; RULES=${RULES:?}; OUT=${OUT:?}; CODEQL=${CODEQL:-codeql}; HERE=$(dirname "$0")
python3 "$HERE/make_split.py" "$BP/expectedresults-0.1.csv" "$OUT/split.json"
# Semgrep: every community Python rule whose metadata CWE is 22, 78, 79 or 643 (list in semgrep_rules.json)
CFG=$(python3 -c "import json,sys;print(' '.join('--config '+sys.argv[1]+'/'+f for f in sorted({r['file'] for r in json.load(open(sys.argv[2]))})))" "$RULES" "$OUT/semgrep_rules.json")
(cd "$BP/.." && semgrep scan $CFG --metrics=off --sarif -o "$OUT/semgrep.sarif" --exclude results --exclude data -q "$(basename "$BP")")
bandit -r "$BP/testcode" "$BP/helpers" "$BP/app.py" -f json -o "$OUT/bandit.json" -q || true
"$CODEQL" database create "$OUT/db" --language=python --source-root "$BP" --overwrite -q
"$CODEQL" database analyze "$OUT/db" codeql/python-queries:codeql-suites/python-security-extended.qls \
  --format=sarif-latest --output="$OUT/codeql.sarif" -q
python3 "$HERE/evaluate.py" "$OUT" development
python3 "$HERE/mechanisms.py" "$OUT" "$BP"
