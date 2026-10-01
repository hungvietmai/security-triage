# Development batch 03: recovered application-caller scans

Recovery run: 2026-10-01. Exploratory JavaScript development only.
[Selection](../../batches/DEVELOPMENT_BATCH_03.md) and the three fixed npm manifests
were published at `f0eee3f5ba6605e3c706f36ef285d7ccb2a40eb3`. This run uses
`9f585d535c9ede2a86b4efaaa4002cc5dc73a316`, including the manifest-preservation fix.
No held-out data, dependency installation in target packages, target-code execution,
new rule/model or suppression policy was used.

## Results from preserved evidence

| Snapshot | Semgrep raw | CodeQL raw | Paired status |
| --- | ---: | ---: | --- |
| nodemon 3.1.14 | 0 | 0 | Completed |
| node-gyp 13.0.2 | 1 | 0 | Completed |
| release-it 21.1.0 | 1 | 0 | Completed |

The four unchanged upstream Semgrep rules (1.178.0) and two CodeQL queries
(CLI 2.27.1, javascript-queries 2.4.6) are the same suite as batches 01–02.
The CodeQL bundle checksum and all 66 locked Semgrep dependency versions were
verified during recovery. Zero output is not a safe-package label.

Both alerts fit the predeclared first-three-per-tool/per-package cap.
[Review notes](review-draft.json) preserve raw references, source hashes, rule
meanings and separate truth/scope fields. Review is assistant-authored, unblinded
and without independent human approval.

- **node-gyp, `lib/node-gyp.js:175`:** the command parameter reaches a generic
  `spawn` helper. Internal build/configure callers select make/MSBuild or Python;
  build selection also supports configured make and `MAKE`. The exported `Gyp`
  class permits other callers and options. A no-shell default does not prove
  safety at this shared site. Technical and scope verdicts remain unresolved.
- **release-it, `lib/shell.js:90`:** the shell-use audit matches `shell: true`,
  but this call is selected only on `win32` for npm/yarn/pnpm at line 89. It is
  **out of the Linux/POSIX scope**, with technical exploitability unresolved.
  This is not an FP or a policy suppression. The alternate call at line 91 is a
  different sink; the platform decision assumes ordinary trusted runtime state.
- **nodemon:** neither configured suite emitted an alert. Process-launch code
  exists in the package; there is no basis for a blanket safe label or recall claim.

Scope exclusions must apply equally to every configuration and receive no
FP-reduction credit. Annotation retains both findings and performs zero suppressions.
No new vulnerability, independent K site, precision, recall or F1 is claimed.

## Recovery and provenance limits

Two local attempts on 2026-09-30 were described in the working conversation, but
their unpushed artifacts were removed during workspace maintenance. Their SARIF,
logs and evidence envelopes are **unavailable** and are not reconstructed or
included in the results above. [summary.json](summary.json) records that gap.
The original manifests and runner fix had already been published and survived.

The earlier attempt exposed a runner bug: it hashed input JSON bytes but saved
a reserialized copy. Extra trailing whitespace could therefore fail the evidence
verifier despite unchanged configuration semantics. The published fix reads each
manifest once, saves its exact bytes and hashes that saved snapshot; a regression
test covers compact JSON, CRLF and trailing whitespace. The recovery run verifies
all case/config hashes against the saved files and passes the annotation verifier.

This report presents a new execution, not recovered original measurements.
The earlier conversation's counts are not a second independent experiment.
No runtime improvement claim is made.

## Coverage and feasibility

Semgrep reports 28, 19 and 27 analyzed targets respectively, with approximately
100% parsed lines. It reports 21 default-ignored paths for release-it. CodeQL has
its own extraction rules; identical archives do not establish identical file
coverage. Target inventories and extraction logs are retained. Dependencies were
not installed. Shipped Python and TypeScript declarations do not constitute
Python/TypeScript vulnerability evaluation.

Batches 01–03 now contain 11 package snapshots and 13 raw alerts, separate from
curling and synthetic probes. They still provide **zero confirmed in-scope FP
units** and no reviewed negative example for constant-command R1. This describes
the chosen sample/rule combination; it does not establish that FP reduction is
impossible. R1 remains unimplemented. Further work should establish independently
adjudicable cases or revise the explicit hypothesis, rather than labeling unknown
command-runner contracts as negative examples.

## Evidence and checks

`npm-*-evidence.json` are gzip/base64 JSON envelopes. Verify `decoded_sha256`,
then decode `source_archive` and `attempts.recovery-20261001.files`, verifying
every inner SHA-256. They contain the exact source archive, raw logs/SARIF,
manifests, configuration and run metadata, including zero-result SARIF. CodeQL
databases are reproducible intermediates and are omitted. Every envelope was
round-trip verified. Only this recovery attempt is present.

[Annotated results](annotated-results.json) use the existing checksum-verifying
module without modifying truth labels. Local recovery checks passed: 22 experiment
tests, 43 frontend tests and 81 backend tests (97.84% backend coverage). Required
pre-commit, commit-message and pre-push hooks passed. These are local results,
not a claim of new Docker execution or remote CI success.
