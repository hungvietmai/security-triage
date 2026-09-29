# First development pilot: curling 0.2.0

Recorded 2026-09-29. This is a working acquisition/scanner integration checkpoint,
not a held-out evaluation or a claim of improved detection.

## Provenance

- Protocol v1.0.0 was committed before scanning:
  `80db12b6f7b275501f9c0f260c90cd05e818491e`.
- Successful attempt's runner/config revision:
  `8ffd191a4b63d74db3b655aeb08c3ce9aa33a4c5`.
- Case: [manifest](../../cases/secbench-curling-0.2.0.json), development split,
  npm `curling@0.2.0`, SecBench.js metadata pinned to
  `5d362353550a8baa42bba34edd26e5fb86d41b60`.
- Source SHA-256:
  `e0e90a2e446bc82282a12b70e21e02cebe7652a93d4259a78adc06e5f1126f54`.
- Independent reference: [GHSA-xmxh-g7wj-8m4m / CVE-2019-10789](https://github.com/advisories/GHSA-xmxh-g7wj-8m4m).
- Semgrep 1.178.0; CodeQL 2.27.1; javascript-queries 2.4.6.
- One unchanged upstream Semgrep rule and two unchanged CodeQL queries:
  [smoke configuration](../../configs/development-smoke-javascript.json).

Tool and configuration hashes are recorded in [run-002.json](run-002.json).
The source was extracted with bounds and path validation. No package install or
exploit execution was performed. The experiment ran natively; the experiment
Dockerfile has not been built in this environment.

## Observed results

| Attempt 002 stage | Status | Raw findings | Elapsed seconds |
| --- | --- | ---: | ---: |
| Source acquisition | Completed | — | 9.14 |
| Semgrep scan | Completed | 0 | 5.77 |
| CodeQL database create | Completed | — | 17.36 |
| CodeQL analysis | Completed | 6 | 40.20 |

Total wall time was 86.30 seconds, including downloads/probes and other runner
overhead. These are single functional-run observations, not comparable benchmark
timings or evidence of speedup; caches and prior execution can affect them.

Semgrep reported two scanned targets, one rule and one file skipped by its default
ignore patterns. CodeQL analyzed the same extracted archive with its own defaults.
File coverage must be aligned and documented before comparing effectiveness.
This small rule selection is not the frozen S0/Q0 baseline suite.

All six CodeQL results use `js/shell-command-constructed-from-input`. Their primary
regions are string concatenations at lines 56, 76, 108, 113, 123 and 128 in
`lib/curl-transport.js`. Each message refers to a related shell-command location
starting at line 56, column 3. This is a candidate many-to-one sink mapping, not
six confirmed independent vulnerabilities. See [raw ledger](findings-002.csv) and
[draft review](review-draft.json). The review is assistant-authored, unblinded and
unapproved; technical/scope verdicts remain unresolved.

No precision, recall, F1, FP reduction or policy benefit is reported. ST, S1,
automatic sink matching and independent labeling are not implemented in this
checkpoint. No held-out case has been run.

## Attempt history and checks

Attempt 001 timed out during Semgrep's version probe. CodeQL completed with six
raw results, but the runner incorrectly classified informational SARIF notices as
partial analysis. Its original run record is preserved unchanged.

The runner now disables Semgrep update/metrics checks and distinguishes
informational notices from warning/error diagnostics. Attempt 002 completed both
tools. Six focused offline tests pass, including archive traversal/link rejection,
retention of findings without locations, failed invocation handling and a
regression check for informational SARIF notices. These checks establish runner
behavior, not scanner accuracy. No evaluation-policy change was needed.

## Preserved evidence

[execution-evidence.json](execution-evidence.json) contains original top-level
artifacts for both attempts (compressed JSON payload): run reports, source archive, case/config snapshots,
rule text, SARIF, CSV and process/version logs. Every artifact has a SHA-256 and an
explicit encoding. Decode the outer JSON `payload` with
`gzip.decompress(base64.b64decode(payload))`, verify `decoded_sha256`, then parse
the decoded JSON. UTF-8 content reconstructs with `.encode('utf-8')`; the source
archive reconstructs with `base64.b64decode(content)`. Verify the recorded hash
before use. Extracted source and CodeQL databases are omitted; the pinned source
archive and scanner configuration allow a fresh run. The redundant expanded
findings JSON is omitted because it duplicates SARIF result objects.

## Next development gate

1. Review the proposed sink aliases and advisory/source evidence; adjudicate
   technical validity and threat-model scope separately. Confirm what enters K.
2. Define the common file scope and representative unmodified S0/Q0 rule suites
   on development cases. The current single-rule smoke result does not establish
   that Semgrep lacks value or justify dropping it.
3. Add the remaining development cases, including Python. Implement the evidence
   policy and S1 as configurations of the same CLI, tracking development effort.
4. Freeze the complete configurations, grouped split, labels and protocol revision
   before any final held-out evaluation.
