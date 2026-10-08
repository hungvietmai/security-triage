# Experiment test conventions

Research scope and freeze gates remain authoritative in `EVALUATION_PROTOCOL.md`
and its amendments. Do not run scanners on frozen pairs to validate test tooling.

- Keep every test suite under `experiments/tests/`, separate from research scripts
  and artifacts. Use one file per workflow/concern, not a mixed catch-all suite.
- Prefer integration tests driving actual CLI/library boundaries with temporary
  manifests, archives and files. Verify persisted JSON, hashes, provenance, errors
  and exclusion reports. Stub only external downloads/scanner processes; do not
  stub the pipeline logic being verified.
- Use unit tests only for necessary algorithm edge cases (diff line ranges, exact
  rename ambiguity, sink span matching, policy predicates). Retain historical
  regressions and identify fixtures explicitly as synthetic test data.
- Run from the repository root:

  ```powershell
  npm --prefix experiments/locators ci --ignore-scripts
  uv run --project backend --with-requirements experiments/requirements-pairs.txt python -m unittest discover -s experiments/tests -p 'test_*.py' -v
  ```

- Test-directory reorganization does not change frozen manifests, locks, reports
  or existing tags. Keep historical log commands intact; update current run guides
  and CI discovery paths when moving tests.
