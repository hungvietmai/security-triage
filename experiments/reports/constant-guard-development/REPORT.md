# Constant integer guard — development checkpoint

`ConstantIntegerGuard.ql` derives **208 > 200 = true** at line 38 of OWASP
`BenchmarkTest01097.py`. This selects a branch when the condition is reached;
it does not prove the sink safe or authorize suppression.

| Check | Observed result |
|---|---|
| Full benchmark | 42 guard facts, all retained |
| Within the 20 CWE-78 files | One fact, at 01097 |
| Authored mechanism cases | 21/21 expectations matched: 9 facts, 12 abstentions |
| Suppressed alerts | 0 |

The counterexample `tainted_after_guard` has the same constant guard but overwrites
the command with user input afterward. It still correctly produces a guard fact.
A suppression policy must additionally establish reaching definitions and command
semantics. In 01097 the selected assignment is line 39, command construction 52,
and sink 55; that association is source-reviewed, not yet automatically proved.

The [query guide](../../../rules/codeql/python-evidence/README.md) defines the
bounded arithmetic, dominating single local definition and unsupported cases.
The pack pins python-all 7.2.6 with CodeQL 2.27.1, compiles with warnings as errors,
and contains no test IDs or benchmark-specific constants. No target code ran.

[Evidence](evidence.json) preserves query/pack/fixtures, expectations, commands,
BQRS, decoded output, checksums and the initial failed compile. The successful
structured run is `constant-guard-development-002`; earlier authoring probes are
not independent samples. The baseline database source hashes match all 20 selected
files. [Summary](summary.json), [benchmark output](benchmark-results.json) and
[fixture output](fixture-results.json) remain available for reproduction.

Validation at this checkpoint: 27 experiment tests, 43 frontend tests and 81
backend tests; backend coverage 97.84%. Required hooks passed. The 21 live fixture
checks are separate from Python unit tests and are not an empirical accuracy score.
No new Docker or GitHub CI result is claimed.

Next: use this evidence in E1 only after definition-to-use and nested-command
obligations are discharged, with an equivalent Q1 control under
[Amendment 01](../../amendments/AMENDMENT_01_QT.md). Until then retain both warnings.
