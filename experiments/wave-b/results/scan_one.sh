#!/usr/bin/env bash
# Wave B: scan one version with the locked configuration. Usage: scan_one.sh VERSION_ID
set -uo pipefail
V=$1; SRC=/tmp/claude-0/-home-claude/efeea80f-89dc-5021-beff-c880931883b1/scratchpad/waveB/vers/$V; OUT=/tmp/claude-0/-home-claude/efeea80f-89dc-5021-beff-c880931883b1/scratchpad/waveB/out/$V; CODEQL=/tmp/claude-0/-home-claude/efeea80f-89dc-5021-beff-c880931883b1/scratchpad/pilot/tools/codeql/codeql; mkdir -p $OUT
log(){ echo "$(date -Is) $*" >> $OUT/run.log; }
log "db create start"; $CODEQL database create $OUT/db --language=python --source-root $SRC --overwrite -q >> $OUT/run.log 2>&1; log "db create end rc=$?"
log "analyze start"; $CODEQL database analyze $OUT/db /tmp/claude-0/-home-claude/efeea80f-89dc-5021-beff-c880931883b1/scratchpad/waveB/q --rerun --format=sarif-latest --output=$OUT/v02.sarif --threads=0 --ram=6000 -q >> $OUT/run.log 2>&1; log "analyze end rc=$?"
log "evidence start"; $CODEQL query run /tmp/claude-0/-home-claude/efeea80f-89dc-5021-beff-c880931883b1/scratchpad/waveB/qt/Evidence.ql -d $OUT/db -o $OUT/evidence.bqrs >> $OUT/run.log 2>&1 && $CODEQL bqrs decode $OUT/evidence.bqrs --format=csv -o $OUT/evidence.csv; log "evidence end rc=$?"
log "semgrep start"; (cd /tmp/claude-0/-home-claude/efeea80f-89dc-5021-beff-c880931883b1/scratchpad/pilot/src && semgrep scan $(sed 's|^|--config rules/|' /tmp/claude-0/-home-claude/efeea80f-89dc-5021-beff-c880931883b1/scratchpad/pilot/out/semgrep_rule_files.txt | tr '\n' ' ') --metrics=off --sarif -o $OUT/semgrep.sarif -q $SRC >> $OUT/run.log 2>&1); log "semgrep end rc=$?"
rm -rf $OUT/db/working $OUT/db/log; log DONE
