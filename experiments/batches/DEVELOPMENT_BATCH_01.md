# Development batch 01 — command/build tooling

Prepared 2026-09-29 before batch scanner execution. This is exploratory development
work after the curling pilot, not a held-out evaluation or complete preregistration.

## Selection and versions

The fixed order is shelljs 0.10.0, execa 10.0.1, npm-run-all 4.1.5, grunt-shell 4.0.0,
and gulp-shell 0.8.0. These five different projects were chosen for their public
command-execution/build-scripting purpose. Exact versions were resolved from npm
registry metadata before scanning; manifests preserve source URL, integrity and
SHA-256. They were not selected on scanner outcomes, downloads or absence of CVEs.
Advisory status is not assessed and is not a negative label. Dependencies are not
installed. Only each published package archive is analyzed; dependency source is
outside these snapshots. Type declarations are not independent TypeScript cases.

The configuration uses unchanged rules from semgrep-rules commit
`a84ff9cc2453ca91d581380de4b8b3f272f6f4be`: detect-child-process,
dangerous-spawn-shell, spawn-shell-true and shelljs-exec-injection. These are the
three generic command/child-process/shell rules plus the ShellJS wrapper rule found
in the pinned JavaScript paths. The AWS Lambda-specific rule is excluded because
this batch is not Lambda handlers. The rules were read before selecting the suite;
no batch scanner outcomes were available. The previously tuned alias rule remains
S1 only and is excluded. Audit-style alerts must be interpreted according to their
actual claim; a correct risky-API warning is not automatically a false vulnerability
claim. Report rule-level results and reasons for any CWE-78 interpretation.

CodeQL retains CommandInjection.ql and UnsafeShellCommandConstruction.ql with the
same pinned pack/hashes as the first pilot. All cases use the same config, 1 thread
and the runner's CodeQL 2048 MB setting. Runs are sequential. Defaults may differ
between engines: record exclusions/parse warnings and do not claim identical
analyzed-file coverage from source equality alone. No detection metrics yet.

## Review order, before observing output

Follow manifest package order. Sort each tool's alerts by relative path, start
line, start column, rule ID and raw ID. Review the first three Semgrep alerts and
first three CodeQL alerts per package; retain the remainder as unreviewed. Missing
locations remain records. Equivalent sites may share explanation after explicit
mapping; raw identities must stay intact. Cap: at most 30 raw alerts, not 30
independent sites. This deterministic capped sample is not a population estimate.

Review source context and package API assumptions, not tool agreement. Keep
technical and scope verdicts separate. An assistant review is disclosed as
unblinded, preliminary, without an independent second reviewer; hypotheses about
FPs are not approved ground truth. Published command-runner APIs may intentionally
accept commands, so determine the precise claim/trust boundary instead of labeling
all external parameters either vulnerable or safe. Do not execute supplied code.

## Execution

From repo root, with pinned native scanners installed:

```bash
python3 -m experiments.run_batch \
  --batch experiments/batches/development-batch-01.json \
  --configuration-commit FULL_COMMIT_OF_THIS_BATCH \
  --semgrep /path/to/semgrep \
  --codeql /path/to/codeql \
  --javascript-query-pack /path/to/codeql/qlpacks/codeql/javascript-queries/2.4.6 \
  --output artifacts/development-batch-01
```

Optional --archive-directory reuses downloaded tarballs named PACKAGE-VERSION.tgz,
with manifest hash verification. Output must be new. The batch runner calls the
same run_pilot.py for every case and keeps failed or zero-result runs in summary.
Do not replace a package after seeing its results. Review and publish evidence even
if the batch yields no confirmed FP. Protocol v1.0.0 remains unchanged.
