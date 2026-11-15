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

---

# Real-stack demo: merging, filtering and the before/after report

**Complete stack, no mocked HTTP.** [adjudication-demo.mjs](adjudication-demo.mjs) opens two
scans the worker already finished and checks, in a real browser, what the thesis demonstration
needs to show. It starts no scanner and fails if the page shows anything other than the
expected values.

Recorded 2026-11-14 on the working tree after commit `1d581a6` (Windows host, Docker Desktop,
Chromium via Playwright on the host, application at `http://localhost:5173`).

| Scan | Profile | Source (development data) |
| --- | --- | --- |
| CWE-78 | `command-injection-v0.2` | `OWASP-Benchmark/BenchmarkPython@f129148`: 51 alerts, 20 candidates, 2 filtered |
| CWE-22 | `path-traversal-v0.2` | `pipecat-ai/pipecat@7519c26`: 3 alerts, all filtered by safety evidence |

| Screenshot | Shows |
| --- | --- |
| [adjudication-scan-overview.png](adjudication-scan-overview.png) | Scan page: main review list and filtered list counts, units table, before/after report |
| [adjudication-merged-candidate.png](adjudication-merged-candidate.png) | One unit holding the alerts of Bandit, CodeQL and Semgrep for the same call |
| [adjudication-single-tool-kept.png](adjudication-single-tool-kept.png) | A call only Bandit reported (`BenchmarkTest00899`, a true positive): kept, with the reason no evidence refutes it |
| [adjudication-filtered-list.png](adjudication-filtered-list.png) | The "Đã gạn" list: two candidates and the rule that filtered each (Semgrep's dead-branch evidence for `01097`, CodeQL's safety evidence for `01098`) |
| [adjudication-filtered-detail.png](adjudication-filtered-detail.png) | A filtered unit reopened: decision, the evidence of both rules it satisfied and its original alerts |
| [adjudication-report.png](adjudication-report.png) | Before/after report: stages, each tool's contribution, filter rules, step timings |
| [adjudication-cwe22-reopened.png](adjudication-cwe22-reopened.png) | A CWE-22 alert removed by safety evidence, reopened from the filtered list |

The script also downloads both exports from the page and checks them: the JSON report has
18 main-list and 2 filtered candidates; the merged SARIF log keeps all 51 alerts and marks only
the 6 alerts of the two filtered candidates as suppressed.

## Reproduce

Start the stack, scan the two sources once (they are development data; see
[experiments/evaluation/collect_development.sh](../../experiments/evaluation/collect_development.sh)),
then pass the two scan IDs to the script. With the frontend's Playwright and Chromium on the
host:

```bash
docker compose up --build -d --wait --wait-timeout 900
python experiments/evaluation/collect_report.py /tmp/owasp command-injection-v0.2 github \
  OWASP-Benchmark BenchmarkPython f1291485808b66e20ddb6b01b10dc71b3df8c8ba
python experiments/evaluation/collect_report.py /tmp/pipecat path-traversal-v0.2 github \
  pipecat-ai pipecat 7519c26ac5508573c35fa3a9c4717b013993d129

cd frontend && npm run test:e2e:install
BASE=http://localhost:5173 OUT=../artifacts/demo-adjudication \
  SCAN_CWE78=<scan_id in /tmp/owasp/report.json> \
  SCAN_CWE22=<scan_id in /tmp/pipecat/report.json> \
  node --input-type=module - < ../docs/demo/adjudication-demo.mjs
```

The script is piped to Node so that `playwright` resolves from `frontend/node_modules`.
This is a demonstration on development data, not an evaluation: the numbers it checks are
the ones recorded in [docs/thesis/chapter-3-results.md](../thesis/chapter-3-results.md).

## JavaScript matching and the constant-command filter (profile v0.3)

**Complete stack, no mocked HTTP.** [js-matching-demo.mjs](js-matching-demo.mjs) opens two
scans the worker finished with profile `command-injection-v0.3` and fails if the page shows
anything else than expected. Both packages are development data.

| Step | Package | What the page shows | Screenshot |
|---|---|---|---|
| Matching | `kill-process-by-name@1.0.5` | Two calls through a two-step alias (`var exec = childProcess.exec`), each with the alerts of CodeQL and ESLint; nothing unmatched. With v0.2 all four alerts were unmatched (queue U) | [js-matching-scan.png](js-matching-scan.png) |
| Decision: kept | same | The call stays in the main review list; the original alerts of both tools are listed | [js-matching-kept-detail.png](js-matching-kept-detail.png) |
| Decision: filtered | `arpping@2.0.0` | One call, reported by ESLint only, is in the filtered list with rule G4 | [js-filtered-list.png](js-filtered-list.png) |
| Reopen | same | The decision shows the evidence rule, the span of the call and the hash of the rule file; the original alert is still there | [js-filtered-detail.png](js-filtered-detail.png) |

```bash
cd frontend
BASE=http://localhost:5173 OUT=../artifacts/demo-js-matching \
  SCAN_KEPT=<scan_id in experiments/evaluation/js-matching-v0.3/inputs/kill-process-by-name_1.0.5/report.json> \
  SCAN_FILTERED=<scan_id in .../inputs/arpping_2.0.0/report.json> \
  node --input-type=module - < ../docs/demo/js-matching-demo.mjs
```

Run on 2026-11-15: all five steps passed. The scan IDs exist only in the local database; scan
the two packages again with profile v0.3 to reproduce.
