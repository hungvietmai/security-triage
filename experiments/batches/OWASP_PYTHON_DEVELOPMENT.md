# OWASP BenchmarkPython CWE-78 development feasibility

This is a new external synthetic development source, not a continuation of the
real npm prevalence survey and not held-out evaluation. No R1 suppressor is active.
Protocol v1.0.0 remains authoritative; all related benchmark cases stay in one
development group. Source and upstream labels were inspected before scanner runs.

## Selection made before scanning

- Repository: https://github.com/OWASP-Benchmark/BenchmarkPython
- Commit: `f1291485808b66e20ddb6b01b10dc71b3df8c8ba` (preliminary v0.1).
- Archive SHA-256: `0defda4cce2ea7675fbeae5b059b4d7cca7d49232529367133feb1adfb529096`.
- Select every row whose CWE is 78 in `expectedresults-0.1.csv`: 20 cases,
  13 expected vulnerable and 7 expected negative. Do not replace unfavorable cases.
- Scan the **entire unmodified source tree**, including helpers and other test
  categories. Keep every raw finding; findings outside the 20 target files have
  a separate inventory and cannot silently disappear from project-level metrics.
- Acquisition uses a pinned GitHub archive through the existing `run_pilot` CLI.
  No application, installation scripts, target subprocesses or exploit is run.
- Labels are separate in `labels/owasp-python-cwe78-expectations.json`. Upstream
  expectation is an independent starting point, not automatic adjudication.

## Scanner selection and interpretation

`configs/development-owasp-python-upstream.json` pins Semgrep 1.178.0, four
unchanged rules from the same upstream revision as the JS survey, and CodeQL
2.27.1 with python-queries 1.8.11 / python-all 7.2.6. The rules cover general
request-to-process flow, system calls, Flask subprocess flow, and the shell=True
audit pattern; the two CodeQL queries cover command injection and unsafe shell
construction. This is a development S0/Q0 candidate, not a final frozen suite.

The audit rule is an API-use warning. Report its results separately from taint
warnings and also show the diagnostic with audit warnings removed. A warning at
an independently safe sink may be a false CWE-78 prediction under our mapping;
it does not imply that Semgrep was wrong about the presence of shell=True. Do
not manufacture a benefit by selecting only this broad rule or call its removal
an R1 result. All four upstream definitions and their exact hashes are retained.

Both tools get the same source snapshot, but their default file/model coverage
can differ. Record parse/extraction issues, default skips, stage times and raw
SARIF; no speedup claim. Keep failed/partial attempts. Runtime measurements are
diagnostics, not controlled repeated timing experiments.

## Review and decision

1. Map target warnings to the unique subprocess call using Python AST containment,
   with a manual check for each mapping. Retain unmatched or ambiguous warnings.
2. Check all seven negative cases against source, route/helper context and the
   Linux/POSIX threat model. Check positives too; a list with an explicit `sh -c`
   remains injection-capable. Dynamic evidence, if needed, must intercept calls
   rather than execute benchmark commands. A bounded probe is not a safety proof.
3. Retain upstream expectation and our technical/scope verdict separately. Mark
   unblinded single-reviewer decisions and any disagreement. Seek second review
   before suppression claims, as required by the protocol.
4. If confirmed in-scope negative sites actually trigger alerts, use them to
   develop evidence queries. CodeQL silence is still insufficient. R1's current
   exclusion of nested interpreters applies: a constant command containing
   `sh -c` requires explicit semantics or a documented development revision,
   never an automatic exemption.
5. If alerts arise only from the audit rule, record that limitation and compare
   the low-cost rule-selection alternative. If no actionable FP exists, report
   the negative result. No hand-written fixture is relabeled as real-project data.

The published implementation/configuration commit precedes this development scan;
it is an external checkpoint, not a claim of held-out pre-registration. The whole
benchmark is now development data and cannot later become a clean test split.

## Native command

Use the Python-specific bundle identified by the configuration (the existing JS
Docker image does not include it). `CONFIGURATION_COMMIT` is the published commit
containing this runner/configuration, not the benchmark source commit.

```bash
python -m experiments.run_pilot \
  --case experiments/cases/owasp-benchmarkpython-cwe78-v01.json \
  --config experiments/configs/development-owasp-python-upstream.json \
  --configuration-commit "$CONFIGURATION_COMMIT" \
  --semgrep /path/to/semgrep \
  --codeql /path/to/python-bundle/codeql/codeql \
  --python-query-pack /path/to/python-bundle/codeql/qlpacks/codeql/python-queries/1.8.11 \
  --output artifacts/owasp-python-development-001
```
