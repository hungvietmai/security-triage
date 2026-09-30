# Development batch 03: concrete CLI/task callers

Selected 2026-09-30 before scanning. This is exploratory development, not a
held-out test or a prevalence sample. [Manifest](development-batch-03.json)
fixes three npm snapshots and their order: nodemon 3.1.14, node-gyp 13.0.2,
release-it 21.1.0. Publish this configuration before executing the scanners and
record that commit in the run. Package bytes were acquired and integrity-checked;
no dependency installation or package execution is required.

The prior eight-package survey has no confirmed in-scope FP. This batch changes
the sampling emphasis to application restart, build and release CLI/task callers.
It does not presume these packages are safe, advisory-free or rich in FPs.
An exported configurable command runner may still lack an attacker boundary;
that remains unresolved rather than automatically becoming a negative label.

Use the unchanged batch-01 configuration: Semgrep 1.178.0, four upstream rules;
CodeQL 2.27.1, two CWE-78 queries from javascript-queries 2.4.6. No S1 rules,
custom models, suppression policy or scan-target adjustments. The primary language
is JavaScript; shipped Python/declarations do not constitute a Python/TS evaluation.
Package dependency source is outside acquisition, so indirect process calls may
depend on analyzer models. Record that limitation instead of labeling zeros safe.

Review package order, then Semgrep/CodeQL order; sort each tool's results by path,
line, column, rule ID and raw ID, and take the first three. Retain every other
result as unreviewed. Inspect complete enclosing functions and callers for those
selected alerts. Record technical truth and threat-model scope separately and
mark assistant/unblinded/independent-review status. Preserve all failed attempts.

Stop after these three snapshots; keep counts even if all are zero or unresolved.
Only propose a negative label if source evidence covers the existing evaluation
unit and input contract. A successful constant/sanitizer fixture is not a real FP;
platform exclusions are not FP-reduction credit. Keep K/N and metrics unfrozen.

The checkpoint is a paired raw-output table, review notes and an explicit decision
on whether this collection supplies evidence for constant-command R1. If not,
report that limitation rather than implementing a permissive suppressor.
