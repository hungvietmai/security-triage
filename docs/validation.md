# Validation evidence

Updated 2026-09-29. Application foundation validation and research evaluation are
separate: the checks below do not establish scanner or adjudication effectiveness.

## Verified GitHub Actions run

- Application commit: `1dbeaf37542aef3c482b7081411c4c8731139595`.
- Run: https://github.com/hungvietmai/security-triage/actions/runs/36094053941
- `frontend`: completed successfully (job `107942407548`).
- `docker-integration`: completed successfully (job `107942407403`).

The run successfully built and started the Docker stack, ran the 12 backend tests
using isolated PostgreSQL schemas, linted Python, checked migration/model drift,
and verified frontend proxy, API readiness and Celery worker connectivity. The
frontend job passed dependency installation, lint and production build.

The initial run found that a boto3 client could not be used directly as a context
manager. The application commit above uses `contextlib.closing` and includes
regression coverage with a real boto3 client and Stubber responses. This tests
client handling; the Docker readiness check separately exercises SeaweedFS S3.

These are results for the linked application commit and run, not a claim that any
future code revision has passed. This documentation update does not rerun Docker.

## Creation workspace checks

The creation workspace had no Docker daemon. Local checks covered frontend build
and lint, Python lint/format, backend tests, Alembic PostgreSQL SQL generation and
Compose configuration. The earlier note reporting 10 tests and Docker execution
as pending described the initial checkpoint; it is superseded by the 12-test
suite and successful GitHub-hosted Docker run above.

An upstream Starlette warning about the httpx/httpx2 transition was observed in
local test dependencies. It was not suppressed.

## Development scanner checkpoint

The manifest-driven CLI acquired pinned npm `curling@0.2.0` and ran Semgrep
1.178.0 and CodeQL 2.27.1 natively. The successful attempt returned 0 and 6 raw
findings respectively. Six focused runner tests passed. Raw outputs, failed
attempt history and configuration hashes are preserved in the
[pilot report](../experiments/reports/curling-0.2.0/REPORT.md).

This is one JavaScript development case with a small smoke configuration. It is
not a frozen baseline comparison. Sink mapping and independent labels remain
pending. The dedicated experiment Dockerfile has not been built or tested;
application CI above does not validate it.

## Not yet validated or implemented

- Python/Git source support in the experiment CLI and complete baseline suites.
- Source upload and provenance schema extensions.
- Automatic sink matching, CWE-78 evidence policy or tuned Semgrep configuration.
- Independent labels, metric computation or held-out evaluation.
- False-positive reduction, recall retention or runtime improvements.

The next research gate is review of the first case's proposed sink mapping and
labels, followed by remaining development cases. See the authoritative
[evaluation protocol](../experiments/EVALUATION_PROTOCOL.md).
