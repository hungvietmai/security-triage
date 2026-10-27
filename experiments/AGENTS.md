# Experiment conventions

Research status, rules and open work live in `../docs/research.md`; the directory
map, run commands and the list of locked documents live in `README.md`. The
current study follows `wave-c/PROTOCOL.md`. `EVALUATION_PROTOCOL.md` and its
amendments govern only the historical CWE-78 phase. Do not run scanners on
frozen pairs or held-out data to validate tooling.

## Locks and records

- Never edit or rename a locked file. A file is locked when its SHA-256 appears
  in a lock manifest; check with `git grep -l "$(sha256sum <file> | cut -c1-64)"`.
  `run_pilot.py` also records `EVALUATION_PROTOCOL.md`'s hash in every `run.json`.
- A change to a frozen method needs a new version and a new lock with the reason
  recorded, never a rewritten lock. Write new results to a new output directory.
- Keep failed acquisitions, failed scans and unfavourable results. Do not replace
  samples after seeing scanner output.
- Data that has been looked at, or used to change a rule, is development data.

## Tests

- Keep every test suite under `experiments/tests/`, separate from research scripts
  and artifacts. Use one file per workflow/concern, not a mixed catch-all suite.
- Prefer integration tests driving actual CLI/library boundaries with temporary
  manifests, archives and files. Verify persisted JSON, hashes, provenance, errors
  and exclusion reports. Stub only external downloads/scanner processes; do not
  stub the pipeline logic being verified.
- Use unit tests only for necessary algorithm edge cases (diff line ranges, exact
  rename ambiguity, sink span matching, policy predicates). Retain historical
  regressions and identify fixtures explicitly as synthetic test data.
- Pass `encoding="utf-8"` to every text-mode `open`, `read_text`, `write_text` and
  `subprocess` call in new or unlocked code; the locale default is cp1252 on Windows.
  Locked scripts cannot be changed: run them with `PYTHONUTF8=1` on Windows.
- Run from the repository root:

  ```powershell
  npm --prefix experiments/locators ci --ignore-scripts
  uv run --project backend --with-requirements experiments/requirements-pairs.txt python -m unittest discover -s experiments/tests -p 'test_*.py' -v
  ```

- Test-directory reorganization does not change frozen manifests, locks, reports
  or existing tags. Keep historical log commands intact; update current run guides
  and CI discovery paths when moving tests.
