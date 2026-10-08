# Real-stack demo: scanning curling@0.2.0 from the UI

**Complete stack, no mocked HTTP.** The built frontend (nginx) calls the real API;
the Celery worker downloads `curling@0.2.0` from the npm registry, verifies its
registry integrity, and runs the pinned Semgrep 1.178.0 and CodeQL 2.27.1 with the
`command-injection-v0.1` profile. This is separate from the Playwright suite in
`frontend/tests/e2e/`, which uses HTTP fixtures and never runs the backend.

Recorded 2026-10-08 on commit `a73aefb` (Windows host, Docker Desktop). The scan
reached `completed` with one **P1** unit: `lib/curl-transport.js:56`,
`child_process.exec`, argument role `shell_command`, decision `D20_STRONG`,
from six CodeQL alerts (no Semgrep alert). The snapshot SHA-256
`e0e90a2e446bc82282a12b70e21e02cebe7652a93d4259a78adc06e5f1126f54` is the archive
the experiment CLI pins, with provenance `publisher_verified`.

| Screenshot | Shows |
| --- | --- |
| [curling-scan-units.png](curling-scan-units.png) | Scan status, snapshot provenance, tool runs, per-priority counts and the P1 unit |
| [curling-unit-evidence.png](curling-unit-evidence.png) | Unit detail: decision, reason, matched conditions, unknowns, predicate values |
| [curling-unit-trace.png](curling-unit-trace.png) | CodeQL message and data-flow trace from `connOptions` (line 64) to the shell command |

## Reproduce

From the repository root, start the stack, then drive the UI with
[real-stack-demo.mjs](real-stack-demo.mjs) from a container on the Compose network:

```bash
docker compose up --build -d --wait --wait-timeout 600
docker run --rm --ipc=host --network security-triage_default   -v "$PWD/docs/demo:/demo:ro" -v "$PWD/artifacts/demo:/out"   -e BASE=http://frontend -e OUT=/out node:24 bash -c   "mkdir /w && cd /w && npm init -y && npm i playwright@1.64.0    && npx playwright install --with-deps chromium    && cp /demo/real-stack-demo.mjs . && node real-stack-demo.mjs"
```

The script creates a project, requests a scan of `curling` `0.2.0` in the form,
waits for the units table (up to 20 minutes), and writes the three screenshots.
The first run took about 2.5 minutes; this recorded run took 28 seconds.

`curling@0.2.0` is the frozen development pair `secbench-curling-0.2.0`, which already
has recorded prior exposure (it is the long-standing development and CI parity case).
This demo adds no new scanner exposure for any held-out or previously unscanned pair,
and it is a demonstration, not a test: the test suites and Playwright fixtures still
never scan research pairs.
