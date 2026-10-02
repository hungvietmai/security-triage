# OWASP BenchmarkPython: first paired development run

The negative-case bottleneck is resolved **for an external synthetic benchmark**:
seven in-scope negative sites have Semgrep warnings, and two also have CodeQL
warnings. This does not establish real-package FP prevalence or a triage gain.
The 11-package npm survey still has no confirmed in-scope FP.

## Provenance and scope

- Review date: 2026-10-02. One completed paired attempt; no failed scanner attempt.
- Published runner/configuration checkpoint before scanning:
  [`4380ee5`](https://github.com/hungvietmai/security-triage/commit/4380ee5fcd155af05cf29a22203de5a8055e228c).
- Benchmark revision: [`f129148`](https://github.com/OWASP-Benchmark/BenchmarkPython/tree/f1291485808b66e20ddb6b01b10dc71b3df8c8ba).
- Selection: all 20 CWE-78 rows, 13 positive / 7 negative expectations, while
  scanning the full source. See the [pre-run memo](../../batches/OWASP_PYTHON_DEVELOPMENT.md).
- The benchmark and its related cases are one **development** group. This is
  exploratory evidence; no held-out gate or pre-registration claim is made.
- Native Semgrep 1.178.0 and CodeQL 2.27.1, python-queries 1.8.11 / python-all 7.2.6.
  Four byte-identical upstream Semgrep rules and two unchanged CodeQL queries.
  Source archive, configs, rules, logs, raw SARIF and normalized rows are preserved
  in [evidence.json](evidence.json). The benchmark archive includes its GPLv3 license.
- No benchmark application, dependency installation hook, target shell command
  or exploit was executed. CodeQL used `--build-mode=none`.

## Observations

Semgrep returned **18 raw findings at 14 sites**; CodeQL **13 at 13 sites**.
All 31 raw findings map inside the unique subprocess AST call in their test file;
the argument/shell-flag spans were manually checked. No outside-target or unmatched
alert was removed: both ledgers are empty in this run. Unit identity uses snapshot,
relative path, call span and argument role, with CWE outside the key.

The following are descriptive counts on the **20 reviewed synthetic sites**, with
one unblinded assistant source review. Upstream expectations and the review agree;
independent human review is pending. They are not final thesis estimates.

| Configuration/diagnostic | TP sites | FP sites | FN sites |
|---|---:|---:|---:|
| Upstream Semgrep candidate S0 | 7 | 7 | 6 |
| Upstream CodeQL candidate Q0 | 11 | 2 | 2 |
| Simple union U0, from saved output | 11 | 7 | 2 |
| Semgrep without shell=True audit, diagnostic only | 2 | 0 | 11 |

ST and S1 remain **not implemented** on this Python set. The last row is an
explicitly predeclared rule-selection diagnostic, not S1 or a policy result.
Removing the audit rule removes seven negative warnings but also loses five true
sites. The two taint rules each report the same two positive sites (00167/00168);
all seven Semgrep negative-site warnings come only from `subprocess-shell-true`.
Its API observation is correct; the negative labels concern a CWE-78 prediction,
not whether the source contains shell=True.

| Partition | True sites | False sites |
|---|---:|---:|
| Semgrep only | 0 | 5 |
| CodeQL only | 4 | 0 |
| Both | 7 | 2 |
| Neither, among independently expected positive sites | 2 | N/A |

The two missed positives are 00899 and 01191, both using the request wrapper.
This is an observed pattern; an extractor/model root cause has not been established.
CodeQL reports only `py/command-line-injection` here; the shell-construction query
ran and returned no findings. Duplicated path messages do not create extra sites.

## Evidence for the seven negative labels

All sites are in scope under shipped HTTP entry points, normal Python semantics
and trusted interpreter/environment. They are technical negatives rather than
platform exclusions. Every case contains an explicit nested `sh -c` command, so
the existing R1 exclusion for nested interpreters still applies to automation.

| Test suffix | Sink line | Source argument for negative CWE-78 label | S / Q warning |
|---|---:|---|---|
| 00350 | 58 | Final dict keyA read overwrites earlier tainted keyB; fixed `a-Value` | yes / no |
| 00512 | 56 | Fresh ConfigParser reads literal keyA `a_Value`; input stored under separate keyB | yes / no |
| 00736 | 55 | Final local dict keyA read yields fixed `a-Value` | yes / no |
| 00900 | 59 | Fresh ConfigParser keyA is independent of query-input keyB | yes / no |
| 01097 | 55 | `7*42-86 > 200` is true; the input-dependent branch is unreachable | yes / yes |
| 01098 | 53 | Exact static route fixes first path segment to `benchmark`; slice yields `benchmar` | yes / yes |
| 01173 | 51 | Helper returns literal `bar`; base64 roundtrip preserves it | yes / no |

These statements follow source semantics, not absence of a CodeQL path. For
01098, the route assumption is essential: assigning an arbitrary request context
and directly calling the nested handler is not the shipped HTTP dispatch model.
For ConfigParser cases, input causing an interpolation exception stops before
the sink and does not overwrite keyA. Constant values here have no shell expansion
or attacker-selected executable/flags. Nested interpreter semantics were reviewed
manually; the scanner policy must not infer the same from a literal alone.

All 13 positive cases are also reviewed in [source-labels.json](source-labels.json),
including the six `subprocess.run` list cases containing an explicit shell. The
technical/scope labels, assumptions, source checksums, reasons and reviewer status
are separate from upstream expectations and from policy decisions.

## What to implement next

Start with an **evidence query for the constant guard in 01097**, and a paired
development counterexample where the guard can select user input. Require a
positive explanation of branch reachability and the resulting command; a missing
taint path is insufficient. Then evaluate whether an explicit, narrow treatment
of the nested interpreter is sound before revising R1 on development data.

Keep 01098 for a separate entry-point/route constraint experiment. It needs a
different proof from arithmetic constant propagation. Do not collapse both into
one heuristic or silently broaden the protocol's R1.

This set currently favors CodeQL alone over the union. Semgrep contributes no
unique true site. Any proposed ST result must therefore be compared with Q0 and
the cheap rule-selection alternative, not only with noisy S0. Seven negatives
are useful mechanism examples but are clustered synthetic templates, not seven
independent real vulnerability families or a sufficient final test set.

## Timing and validation

One native run: Semgrep scan 3.94 s; CodeQL database creation 27.50 s and analysis
18.15 s; total CLI 52.35 s including acquisition/version checks. No repeated timing
experiment or speedup claim. Semgrep reports 1,236 targets, approximately 100%
parsed lines, one size skip and one default-ignore skip. CodeQL completed with no
warning/error-level SARIF diagnostics. Both share the archive, not necessarily
the exact effective file/model coverage.

- 25 focused experiment tests passed, including pinned GitHub identity validation,
  language/config mismatch rejection, correct query-pack selection and prior JS
  acquisition/provenance regression checks.
- Required hooks passed: pre-commit, commit-msg, pre-push (43 FE / 81 BE tests,
  backend coverage 97.84%). No new Docker build or GitHub CI result is claimed.
- All retained bytes round-trip through the envelope with matching SHA-256s.
  Reconciliation preserves 31/31 findings, checks source/manifest/SARIF hashes,
  and produces the reviewed summary from the saved run and separate source labels.
- Upstream rule whitespace was preserved deliberately to retain exact hashes.

## Reproduce the reconciliation

```bash
python experiments/reports/owasp-python-development/reproduce.py \
  --run artifacts/owasp-python-development-001 \
  --output /tmp/owasp-python-summary.json
```

`evidence.json` contains gzip-compressed JSON encoded as base64. Verify
`decoded_sha256` after decompression; inner `files` each contain base64 bytes and
their SHA-256. Restore these ordinary files into a new run directory, then safely
extract `source.tgz` using `experiments.run_pilot.unpack` and `case.archive_root`.
The CodeQL database is reproducible and omitted; the entire original source
archive and both raw SARIF reports are included. `reproduce.py` is report-specific
AST reconciliation and counting, not an adjudication algorithm.

Primary references: [OWASP Python benchmark description](https://owasp.org/projects/benchmark?tab=python-test-cases),
[pinned upstream expected results](https://github.com/OWASP-Benchmark/BenchmarkPython/blob/f1291485808b66e20ddb6b01b10dc71b3df8c8ba/expectedresults-0.1.csv),
[Python subprocess semantics](https://docs.python.org/3/library/subprocess.html),
[Flask routing](https://flask.palletsprojects.com/en/stable/quickstart/#routing).
