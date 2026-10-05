# Python evidence queries

This pack is separate from upstream baseline queries. It uses the pinned
`codeql/python-all` 7.2.6 bundled with CodeQL 2.27.1. It contains no sink names,
benchmark test IDs, filenames or special cases for 86, 208 or 200.

`ConstantIntegerGuard.ql` returns a table describing a comparison's outcome
**when evaluated**, plus its source coordinates. It does not say the condition
is reached, the selected branch is safe, its values reach a sink unchanged, or
the whole function is safe. Its output must never directly suppress an alert.

Supported evidence:

- Integer literals and unary `+`/`-`; binary `+`, `-`, `*`.
- Each evaluated intermediate value must lie in [-10000, 10000]. This prevents
  QL's bounded integer arithmetic from being confused with Python's arbitrary
  precision integers. Multiplication inputs are bounded before calculation.
- A name may resolve only to a non-parameter fast local with one plain integer
  literal assignment, no other store/deletion, and no escape to another scope.
  The assignment must dominate every CFG occurrence of that read.
- One comparison operator: `>`, `>=`, `<`, `<=`, `==`, `!=`.
- Standard Python execution; reflective frame mutation, debugger/native memory
  rewriting and arbitrary runtime code injection are outside this proof model.

Unknown values, calls/coercions, floating point, chained comparisons, globals,
closures, multiple writes and numbers outside the bound yield no evidence. Absence
means unsupported/inconclusive, not a negative vulnerability prediction. The
literal-only name rule deliberately rejects many expressions that could be
proven constant by a richer analysis.

The proof concerns the integer guard only. A later overwrite of the command, an
unsafe constant command, nested interpreters or another path to a sink requires
separate analysis. Existing protocol R1 exclusions remain unchanged.

Run from the repository root after the paired Python benchmark scan:

```bash
python -m experiments.diagnostics.run_constant_guard \
  --benchmark-run artifacts/owasp-python-development-001 \
  --codeql /path/to/python-bundle/codeql/codeql \
  --output artifacts/constant-guard-check
```

The development-only helper shares the scan runner's process/version utilities,
reuses the baseline database and creates a static-only fixture database. It saves
the exact query, fixture and expectation bytes, commands, failures, BQRS, decoded
results and checksums. It neither changes baseline queries nor runs benchmark or
fixture commands. The 21 authored cases check semantics and abstention; they are
not independent evaluation data. No trained model is involved.

Library references: [Python control flow](https://codeql.github.com/docs/codeql-language-guides/analyzing-control-flow-in-python/),
[Variable API](https://codeql.github.com/codeql-standard-libraries/python/semmle/python/Variables.qll/type.Variables%24Variable.html),
[IntegerLiteral API](https://codeql.github.com/codeql-standard-libraries/python/semmle/python/Exprs.qll/type.Exprs%24IntegerLiteral.html).
