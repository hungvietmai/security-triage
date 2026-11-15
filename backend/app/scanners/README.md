# Scanner integration

Subprocess adapters and source acquisition shared by the Celery worker
(`app/workflows/scans/`) and the experiment CLI (`experiments/run_pilot.py`).
Changes here change both; CI's `scan-parity` job requires them to agree.

| Module | Role |
|---|---|
| `sources.py` | Server-built npm/GitHub download URLs; npm registry integrity check |
| `acquisition.py` | Bounded archive extraction: 50 MiB download, 200 MiB unpacked, 20,000 entries; rejects traversal and outward symlinks, skips symlinks inside the archive |
| `semgrep.py`, `codeql.py`, `process.py` | Scanner adapters; each command runs with an argument list and a timeout in its own process group, with logs preserved. `codeql.run_codeql_evidence` runs pinned safety-evidence queries on the database the scan already created (the adjudication step) |
| `bandit.py`, `eslint.py` | Screening adapters for profiles that add them. Both run from pinned worker configuration (`tools/bandit`, `tools/eslint`) and never load configuration, plugins or a formatter from the scanned source. ESLint paths are made relative to the source root; a file it cannot parse makes its run partial |
| `pipeline.py` | Runs the configured tools for one language, optionally in parallel, preserving configured order; rejects a scanner whose version differs from the configuration |
| `sarif.py` | Strict SARIF 2.1.0 parsing; malformed arrays fail, runs without results are partial |
| `profile.py` | Loads a scan profile (`profiles/<id>/profile.json`) and verifies the SHA-256 of every file it names. Priority profiles pin rules, rule claims, a policy and the configuration of any screening tool (Bandit, ESLint) their language configs add; `safety-evidence` profiles pin a CodeQL query pack with a baseline and an evidence query |
| `provenance.py` | Artifact hashing helpers; `pinned_file` resolves a configured `{path, sha256}` file inside the repository |

Rules:

- Use an argument list, never shell interpolation of paths.
- Never execute scanned source or install its dependencies.
- Preserve raw SARIF, logs, tool/rule versions, the source snapshot and partial failures;
  a failed or timed-out tool is never reported as zero findings.
- Keep tool agreement, triage priority and evaluation labels separate.
- Check the CodeQL terms for the intended repositories and deployment before distributing its CLI.

## Semgrep target selection

A language configuration may set `semgrep_target_selection` (profile `command-injection-v0.3`
uses `worker-controlled-v1`). `control_semgrep_targets` in `semgrep.py` then removes every
`.semgrepignore` from the extracted source and writes one at its root that ignores only
`node_modules/`. Without it Semgrep skips `build/`, `dist/`, `test/` and similar folders by
default, and a `.semgrepignore` shipped inside the scanned source can hide files from the
detection rules, the sink locator and the evidence rules. Profiles without the setting keep
Semgrep's default selection.
