# Initial validation

Checked in the creation workspace:

- Frontend dependency installation, TypeScript compile and Vite production build.
- Frontend Oxlint and Prettier checks.
- Backend Ruff lint and formatting.
- 10 API/readiness tests passed with isolated SQLite databases. PostgreSQL tests
  use unique per-test schemas when TEST_DATABASE_URL is present (Docker/CI).
- Alembic migration compiled to PostgreSQL SQL without errors.
- Compose YAML parsed and local build/config paths checked.

The creation workspace has no Docker daemon. Docker images have not been built
or started here, and PostgreSQL/S3/worker integration has not been executed here.
The included GitHub Actions workflow is configured to run those checks after push;
its presence is not evidence that CI has passed. The startup command must still be
verified on a Docker host.

Python test dependencies emit an upstream Starlette warning about the transition
from httpx to httpx2. Current tests pass; no warning is hidden.
