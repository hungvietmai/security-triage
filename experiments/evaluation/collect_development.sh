#!/bin/sh
# Collect exported reports for the development sources used in experiments/evaluation.
# Every source below is development data that earlier phases already scanned
# (experiments/cases/, wave A and wave C). No frozen pair or held-out source is listed.
# Run from the repository root with the stack up: sh experiments/evaluation/collect_development.sh
set -u
out=experiments/evaluation/inputs
collect() { PYTHONUTF8=1 python experiments/evaluation/collect_report.py "$@" || echo "FAILED: $*"; }

# CWE-78, Python: OWASP BenchmarkPython (20 labeled CWE-78 sites).
collect "$out/owasp-benchmarkpython-v0.2" command-injection-v0.2 github \
  OWASP-Benchmark BenchmarkPython f1291485808b66e20ddb6b01b10dc71b3df8c8ba

# CWE-78, JavaScript: curling and the eleven npm packages of development batches 01-03.
for spec in curling@0.2.0 execa@10.0.1 grunt-shell@4.0.0 gulp-shell@0.8.0 \
  launch-editor@2.14.1 node-gyp@13.0.2 node-notifier@10.0.1 nodemon@3.1.14 \
  npm-run-all@4.1.5 open@11.0.4 release-it@21.1.0 shelljs@0.10.0; do
  name=${spec%@*}
  version=${spec#*@}
  collect "$out/npm-$name-$version-v0.2" command-injection-v0.2 npm "$name" "$version"
done

# CWE-22, Python: one repository whose alerts v0.2 keeps and one whose alerts it removes.
collect "$out/flask-admin-cwe22-v0.2" path-traversal-v0.2 github \
  pallets-eco flask-admin 4f8be4580b082c6047492baa801f3f08642c9a75
collect "$out/pipecat-cwe22-v0.2" path-traversal-v0.2 github \
  pipecat-ai pipecat 7519c26ac5508573c35fa3a9c4717b013993d129
