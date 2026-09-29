# Development batch 01 — results and review checkpoint

Date: 2026-09-29. Exploratory development only; no held-out data were run.
[Selection and review order](../../batches/DEVELOPMENT_BATCH_01.md) were fixed
before scanner execution. Configuration commit: `7b3a26b4dbdec7f3ece438dbe1384af905e80375`.
The branch was updated after execution, so this is **not** an externally timestamped
preregistration. The evaluation protocol remains unchanged.

## Observed results

| Published snapshot | Semgrep raw alerts | CodeQL raw alerts | Selected paired attempt |
| --- | ---: | ---: | --- |
| shelljs 0.10.0 | 1 | 0 | recovery |
| execa 10.0.1 | 0 | 0 | attempt-2 |
| npm-run-all 4.1.5 | 0 | 0 | attempt-2 |
| grunt-shell 4.0.0 | 1 | 0 | attempt-2 |
| gulp-shell 0.8.0 | 4 | 0 | attempt-2 |

All selected paired attempts completed. Semgrep 1.178.0 used four unchanged
upstream rules; CodeQL 2.27.1 used the two configured CWE-78 queries from
javascript-queries 2.4.6. These counts describe this suite, not every query each
product provides. Five detect-child-process alerts and one spawn-shell-true audit
alert were emitted. The custom alias rule was excluded and remains S1 work.

Six alerts point to three candidate call sites. This is a mapping observation,
not three confirmed vulnerabilities or six confirmed false positives. CodeQL's
zero results do not decide truth labels. Precision, recall, F1 and FP reduction
remain uncomputed; there are no independently approved labels in this batch.

## Failures retained

1. Attempt 1: Semgrep could not start because the previous virtual environment's
   Python executable was missing. All five Semgrep outcomes are failed/unavailable,
   not zero. CodeQL completed with zero alerts on all five snapshots.
2. Restored the exact Semgrep lock file in a fresh environment. Attempt 2 completed
   for four packages. shelljs extraction succeeded but CodeQL analysis failed with
   `DBError: Unknown string encoding: 21`; no SARIF was produced. Semgrep reported
   one alert there. The runner's existing exception handler overwrote analysis
   metadata, so do not reconstruct an exit code or duration for that failed step.
   Original stderr is preserved. Cause is undetermined.
3. A fresh paired shelljs recovery completed with one Semgrep alert and zero
   CodeQL alerts. It is identified separately; prior failures were not erased.

No runtime superiority claim is made. The tail of attempt 1 briefly overlapped
with the beginning of attempt 2; resource contention was not controlled. Scans
otherwise followed the sequential runner. Durations are diagnostic logs only.
No package dependencies, package code, or exploit code were executed.

## Preliminary source review

The predeclared cap selects five of the six raw alerts. Review is unblinded,
assistant-authored and pending human approval. Technical and threat-model labels
are both unresolved. One remaining gulp-shell alert is explicitly unreviewed.

| Site | Evidence inspected | Remaining question |
| --- | --- | --- |
| shelljs `src/exec.js:147` | `execAsync` passes `cmd` into `child.exec`; README documents arbitrary shell execution and caller sanitation | Which caller supplies untrusted command fragments across a security boundary? |
| grunt-shell `tasks/shell.js:46` | Command comes from task data/callback and template processing; rule names framework object `grunt` as source | Does framework-object taint correspond to attacker-controlled command bytes in a concrete task? |
| gulp-shell `lib/index.js:36` | Command template uses `file`/template data; shell defaults true but is overridable | Which template and input permit injection, and what is the effective shell setting? |

For gulp-shell, selected raw IDs are `semgrep:0:0` (shell audit), `semgrep:0:1`
(command argument), and `semgrep:0:2` (file argument). `semgrep:0:3` (options)
is outside the cap. The audit message is broader than the evidence on every call:
`options.shell` can be false, but defaults true. That alone does not establish
that this site is a false positive. Conditional risky-API warnings must not be
silently evaluated as unconditional vulnerability claims.

The reviewed commands are not proven constants at the sink. This batch therefore
provides no approved negative example for R1's proposed constant-command exclusion.
Do not implement a policy that turns intended command-runner APIs into automatic
FPs or interprets missing CodeQL paths as evidence of safety.

## Coverage and limits

Semgrep logs report 38, 142, 23, 1 and 2 analyzed targets respectively, with
approximately 100% parsed lines. Execa's 33 TypeScript targets and gulp-shell's one
TypeScript target are declarations, not a TypeScript vulnerability evaluation.
Source inventories and CodeQL extraction logs are retained. Matching archive
hashes do not establish identical analyzed-file coverage or dependency coverage.
Only published package contents were scanned; callers and dependency source were
not added. This purposive command-library sample is not an FP prevalence estimate.
Advisory absence was not checked and is not used as a negative label.

## Evidence and next action

- `summary.json`: selected attempts and all statuses, with failures retained.
- `review-draft.json`: all raw findings, deterministic review selection and notes.
- `npm-*-evidence.json`: lossless gzip/base64 envelopes. Decode `payload`, verify
  `decoded_sha256`, then decode each file's base64 `content` and verify its SHA-256.
  Each envelope contains all attempt-level top-level logs/SARIF/config/manifests,
  plus one original source archive. CodeQL databases are reproducible intermediates
  and are omitted. Zero-result SARIF is retained.

**Next:** review curling and these five selected alerts with a human reviewer,
then fix a second development batch of applications/build tasks with inspectable
callers and documented input boundaries. Preserve batch 01 as unresolved evidence.
Choose the next cases before running, using API usage and available caller context,
not expected labels. A small synthetic safe/unsafe fixture may test plumbing but
must stay separate from real-data evaluation. R1 implementation awaits a defensible
negative example and an explicit evidence condition. Python remains unimplemented.

Validation on the current remote application snapshot: 43 frontend tests and 81
backend tests passed through the pre-push hook; backend coverage 97.84%. Experiment
suite: 14 tests before this batch. Root pre-commit and commit-message hooks passed
for the batch configuration; no app files were changed. These are local checks,
not a claim about remote CI or a new Docker execution.
