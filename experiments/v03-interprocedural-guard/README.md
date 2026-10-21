# v0.3 — interprocedural, exception-based path guards (CWE-22)

- Current decision: [DECISION_2026-10-20.md](DECISION_2026-10-20.md). Freeze both modes;
  retain strict as the default and report scoped under all four published assumptions.
  Independent evaluation is prepared in [wave C](../wave-c/PROTOCOL.md); no new scan has run.
- `FREEZE_v0.3_dual.sha256` uses repository-root-relative paths and preserves the historical
  strict freeze. Verify from the repository root with
  `python experiments/v03-interprocedural-guard/scripts/verify_freeze.py --metadata experiments/v03-interprocedural-guard/FREEZE_v0.3_dual.json`.
  Archive bytes remain under ignored `artifacts/v03/`; metadata records their hash.
- `SPEC.md`: specification (second-review corrections, the sink-contract decisions, levels A/B). Level A steps
  (a) `Segment`, (b) `SafeRel` and (c) `Contained` are implemented.
- `SPEC_RESOURCE.md`: the one-round addition of resource-derived contracts (evidence levels `proved` / `scoped`,
  the resource-root conditions, the published assumptions and the stop condition). `FREEZE_v0.3_strict.sha256` locks
  the strict baseline before that round (archive `../../artifacts/v03/v03_strict_baseline.tar.gz`).
- Two modes: `ql/queries/cwe22_v03.ql` (strict, `st/cwe-22/v03`: declared and local contracts) and
  `ql/queries/cwe22_v03s.ql` (scoped, `st/cwe-22/v03s`: also resource contracts); `ql/queries/V03Resources.ql` lists
  resource-root candidates with the evidence or the failed condition.
- `counterexamples/resources.py` (+ `resources_admin.py`, `tests/test_resources.py`), `counterexamples_tmpdir/`,
  `policy_scenarios/resources/`, `expectations/resources_expectations.csv`: the resource-contract counterexamples.
- `ql/`: the v0.3 query pack. `IpgGuard.qll` derives facts as must-properties of control-flow nodes from a closed
  rule list and separates `contained` (ProvenContained) from `allowedRoot` (AllowedRoot: declared contract, the
  root of a containment check on the sink value itself, or a resource contract in scoped mode).
  `queries/cwe22_v03.ql` is the v0.2 `all` query plus the one
  v0.3 suppression; `queries/V03Evidence.ql` lists suppressed sinks (root, basis, contract source);
  `queries/V03Contracts.ql` lists allowed and contained roots per sink; `queries/V03Summaries.ql` (diagnostics) lists
  validator summaries and containment calls whose root is not trusted. `ext/` makes the contract empty by default.
  Depends on `../owasp-bp-pilot/ql_v02`.
- `policy/`, `policy_scenarios/`: model packs with declared contracts — test data for the counterexample scenarios
  (`declared`, `wrong_root`, `conflict`; `none` loads no pack).
- `counterexamples/ipg.py`: 19 safe (`ipg_<n>_good`) and 26 dangerous (`ipg_<n>_bad`) cases;
  validators in a separate module. Resource cases have their own expectation table.
- `expectations/`: the expected outcome of every (scenario, case), written from the fixture semantics and locked by
  `EXPECTATIONS.sha256` before the first step (c) run.
- `scripts/check_semantics.py`: checks the expectations table by executing the fixture logic on a 29,929-string corpus
  (no file reads or writes). Finite testing, not a proof.
- `scripts/evaluate_scenarios.py`: scores a scenario's QL results against the table (UNSOUND / VACUOUS / MISSED / ok).
- `scripts/subset_check.py`: checks `R(later) ⊆ R(earlier)` along a variant chain, keyed by (CWE, file, line, column).
- `scripts/run_cex.sh WORK_DIR`: counterexample runs in both modes (SPEC §8 criteria 1, 2, 5, 6). Results:
  `results/cex_resource_round.json` (this round, with a case-by-case comparison of strict against the frozen
  baseline); `results/cex_stage1_abc.json` and `results/cex_stage1_ab.json` are the earlier runs. Each records the
  sha256 of every input file.
- `scripts/run_dev.sh WORK_DIR` with `scripts/contract_report.py`: v0.3 strict and scoped without a declared
  contract on the wave B development versions (mlflow, Django) and BenchmarkPython (criteria 3, 4), with per-alert
  contract coverage. Results: `results/dev_resource_round.json` (this round), `results/dev_stage1_abc.json` (earlier).

Development data: the F1 alerts and RC-M6 of wave B (`../wave-b/results/wave_b_labels.csv`, locked by
`../wave-b/results/LABELS_LOCK.sha256`). Evaluation must use repositories selected and locked before scanning, with
no declared contract written after looking at their alerts.

The v0.2 pack this compares against is locked in `../owasp-bp-pilot/FREEZE_v0.2_postformat.sha256`
(see `../owasp-bp-pilot/FREEZE_DEVIATION.md`).
