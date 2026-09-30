# Rule-claim annotation of retained development results

2026-09-30. Offline postprocessing using `rule-claims-v1`; no rescanning, query
changes, suppression or truth-label approvals. The rule mapping was developed
after seeing the development results. This is not held-out validation.

## Real packages: both fixed batches

Selected runs are batch 01's shelljs recovery and four successful attempt-2 runs,
plus batch 02's three successful attempt-2 runs. Acquisition manifests, original
failures and raw scanner evidence remain in their original reports. Checksums of
all input configuration/SARIF files were verified before annotation.

| Claim kind | Raw findings |
| --- | ---: |
| Conditional function-argument flow (Semgrep; upstream audit category) | 9 |
| Shell usage audit (Semgrep) | 1 |
| Modeled library-input command construction (CodeQL) | 1 |
| **Total preserved** | **11** |

All eight packages, including zero-alert packages, are represented in
`annotated-results.json`. All 11 results are mapped CWE-78 candidates and remain
unresolved for truth/scope at this stage. This grouping neither turns the ten
upstream audit-category results into confirmed vulnerabilities nor discards them
from the candidate set. **Automatic suppressions: 0. Accuracy metrics: unavailable.**

## Synthetic diagnostic, reported separately

The ten R1 probes contribute nine raw results: two conditional function-argument
flows, two shell usage audits, one interpreter-argument warning, one wrapper-call
warning and three CodeQL library-construction flows. All nine were preserved.
They are synthetic mechanism checks and are not pooled into real-package accuracy.

## What changed

The project now has a versioned definition of rule claim meanings and a runnable
annotation command. CWE identifiers are normalized for display and linked to
MITRE without losing original tags or asserting a CWE-78/88 reclassification.
Unknown rules and mismatched versions/hashes stay visible and unresolved. Sink
association and human labels remain separate from this module.

This is the normalization/linking control described in the protocol, not ST's
adjudication algorithm and not an improvement result. A future evaluator must
use the same candidate interpretation for each configuration and retain unknown
classification/mapping coverage rather than silently dropping difficult findings.

## Validation and next task

21 offline experiment tests pass (six new regression tests for claim mapping),
covering audit retention, missing locations, unknown/near-match IDs, tool/rule
pin changes, multiple CWE tags, SARIF tampering, completed-but-missing output,
and failed-scan unavailable counts. App hooks also pass locally: 43 frontend and
81 backend tests, backend coverage 97.84%. No new Docker execution is claimed.

Next, use this common interpretation when labeling real cases at the existing
location/argument-role unit. The R1 fixture report identifies explicit interpreter
calls as a useful search stratum; finding a real example with inspectable caller
input is the next data task. Do not treat the synthetic complementarity result or
node-notifier's bounded quoting checks as real-data FP reduction.
