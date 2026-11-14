# Scanner integration

Subprocess adapters and source acquisition shared by the Celery worker
(`app/workflows/scans/`) and the experiment CLI (`experiments/run_pilot.py`).
Changes here change both; CI's `scan-parity` job requires them to agree.

| Module | Role |
|---|---|
| `sources.py` | Server-built npm/GitHub download URLs; npm registry integrity check |
| `acquisition.py` | Bounded archive extraction: 50 MiB download, 200 MiB unpacked, 20,000 entries; rejects traversal and outward symlinks, skips symlinks inside the archive |
| `semgrep.py`, `codeql.py`, `process.py` | Scanner adapters; each command runs with an argument list and a timeout in its own process group, with logs preserved |
| `pipeline.py` | Runs the configured tools for one language, optionally in parallel, preserving configured order; rejects a scanner whose version differs from the configuration |
| `sarif.py` | Strict SARIF 2.1.0 parsing; malformed arrays fail, runs without results are partial |
| `profile.py` | Loads a scan profile (`profiles/<id>/profile.json`) and verifies the SHA-256 of every file it names. Priority profiles pin rules, rule claims and a policy; `safety-evidence` profiles pin a CodeQL query pack with a baseline and an evidence query |
| `provenance.py` | Artifact hashing helpers |

Rules:

- Use an argument list, never shell interpolation of paths.
- Never execute scanned source or install its dependencies.
- Preserve raw SARIF, logs, tool/rule versions, the source snapshot and partial failures;
  a failed or timed-out tool is never reported as zero findings.
- Keep tool agreement, triage priority and evaluation labels separate.
- Check the CodeQL terms for the intended repositories and deployment before distributing its CLI.
