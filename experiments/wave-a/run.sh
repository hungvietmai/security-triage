#!/usr/bin/env bash
# Wave A run for one project: CodeQL DB, v0.2 none/all queries, evidence table, Semgrep.
set -euo pipefail
A=$1; NAME=$2; CODEQL=$3
OUT=$A/out/$NAME; mkdir -p $OUT
log(){ echo "$(date -Is) $*" >> $OUT/run.log; }
log "db create start"; $CODEQL database create $OUT/db --language=python --source-root $A/src/$NAME --overwrite -q >> $OUT/run.log 2>&1; log "db create end"
log "analyze start"; $CODEQL database analyze $OUT/db $A/q --rerun --format=sarif-latest --output=$OUT/v02.sarif --threads=0 --ram=6000 -q >> $OUT/run.log 2>&1; log "analyze end"
log "evidence start"; $CODEQL query run $A/qt/Evidence.ql -d $OUT/db -o $OUT/evidence.bqrs >> $OUT/run.log 2>&1; $CODEQL bqrs decode $OUT/evidence.bqrs --format=csv -o $OUT/evidence.csv; log "evidence end"
log "DONE"
