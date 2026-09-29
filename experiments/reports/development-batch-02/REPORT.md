# Development batch 02 — application-helper results

Exploratory development run, 2026-09-29. Configuration
`d5326b1c2728db39c2a64df092a3cd38f295daac` was published before scanner execution.
See [selection](../../batches/DEVELOPMENT_BATCH_02.md). This is not a held-out test
or an overall study preregistration. The same batch 01 scanner configuration was
used: four unchanged upstream Semgrep rules, two CodeQL CWE-78 queries, pinned
versions 1.178.0 and 2.27.1 respectively. No tuned alias rule or policy was added.

## Results

| Published package | Semgrep raw alerts | CodeQL raw alerts | Paired status |
| --- | ---: | ---: | --- |
| open 11.0.4 | 0 | 0 | completed, attempt 2 |
| node-notifier 10.0.1 | 2 | 1 | completed, attempt 2 |
| launch-editor 2.14.1 | 2 | 0 | completed, attempt 2 |

All five raw alerts fit the predeclared per-tool/per-package review cap. Notes are
preliminary, unblinded and assistant-authored; technical and scope verdicts remain
unresolved, with zero approved labels. No precision/recall/F1 or FP reduction is
claimed. Zero alerts concern the selected queries and snapshot, not package safety.

## What this batch contributes

- **node-notifier:** both tools report `lib/utils.js:59`. CodeQL provides five paths
  from notification input. The caller fixes the executable, allowlists option names
  and passes values through escaping/quoting. Some reported paths skip those branches
  or follow a non-string branch. This is a concrete candidate for type/call-context
  review. [Sanitizer review](SANITIZER_REVIEW.md) records exact source locations,
  assumptions and unresolved proof obligations. It is not an approved FP or an
  implemented sanitizer model. The exported generic helper remains broader than
  the inspected NotifySend caller, so its shared sink cannot be marked safe globally.
- **launch-editor:** Semgrep reports `specifiedEditor` reaching Windows `exec` at
  `index.js:167` and non-Windows `spawn` at `:172`. `guess.js:65-68` parses the specified
  editor into program and arguments. This warning is about executable selection,
  not merely shell metacharacters in a filename. A no-shell call or existing-file
  guard is not sufficient negative evidence. Windows escaping warrants separate
  platform-specific review. CodeQL's zero count does not decide either label.
- **open:** neither selected suite reported a finding. There is no alert to review
  and no basis for a blanket safe label or a recall conclusion.

Within raw-output mapping only, there is one candidate call site reported by both
and two by Semgrep alone. This is not a TP complementarity table; confirmed truth
and an independent reference set are still absent. No "both missed" count exists.

## Environment failures and recovery

Attempt 1 retained three Semgrep failures: its virtual environment's interpreter
entry was missing following workspace maintenance. CodeQL completed with counts
0, 1, 0. These Semgrep failures are unavailable outcomes, never zero findings.

Restored the missing interpreter link to the same Python 3.12.14 runtime and
verified all 66 package versions against the Semgrep lockfile. A fresh-environment
installation was also attempted and eventually completed; the selected retry uses
the restored original environment, whose exact path is in run.json. Both complete
batch attempts are preserved. Attempt 2 successfully ran both tools sequentially.
No dependency/package/native executable was executed as part of source acquisition
or scanning. Timing is diagnostic only; no speedup comparison is made.

## Evidence and limitations

`summary.json` records both attempts. `review-draft.json` preserves every raw result
and source-review notes. Each `npm-*-evidence.json` envelope contains original
attempt-level reports, logs, SARIF and all UTF-8 non-NUL source files from the
published archive. Binary vendor files are listed with hashes and sizes; archives
and CodeQL databases are omitted from Git evidence. Original archive URLs and
SHA-256 plus registry integrity remain in the manifests for recovery. Decode and
verify the outer SHA-256 and then every inner base64 file's SHA-256 before reuse.
Dependencies and downstream applications were not included. These three helpers
still do not provide every application's trust boundary. This deliberate sample
is useful for mechanism inspection, not population-level FP prevalence.

## Next checkpoint

Review node-notifier's concrete paths and the curling case with a human reviewer.
A conservative policy should retain unresolved locations. Decide whether the
current evaluation unit can support a negative label for node-notifier without
ignoring other callers. Do this before expanding to more random packages or
building a general sanitizer engine. Constant-command R1 still lacks a confirmed
negative example. Python remains outside the implemented adapter.

Local validation: 15 experiment tests, 43 frontend tests and 81 backend tests pass;
backend coverage 97.84%. Repository pre-commit, commit-message and pre-push hooks
were run. No application code changed; this does not assert a new Docker run or
remote CI success.
