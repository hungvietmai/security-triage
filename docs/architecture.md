# Architecture and scope

This repository is the initial development foundation, not a working vulnerability scanner.

## Implemented

- React/TypeScript project creation and paginated project list; honest loading/error/empty states.
- FastAPI project creation/list/detail endpoints, liveness and dependency readiness.
- SQLAlchemy foundation: projects → source_snapshots → scans → tool_runs → findings.
- Immutable Alembic migration file, UUID keys, foreign keys, uniqueness and status constraints.
- Redis/Celery worker and diagnostic ping task; S3 client and idempotent bucket initializer.
- Docker runtime builds, development override, persistent database/broker/object-store volumes.
- Tests and CI configuration. Readiness checks PostgreSQL/schema, Redis and S3;
  worker availability is a separate Docker healthcheck.

## Next milestones

1. Folder picker → filter preview → browser ZIP → bounded upload → immutable source snapshot.
2. Isolated Semgrep process → raw SARIF storage → normalized findings → result screen.
3. CodeQL extraction/query execution for Python and JS/TS; preserve logs and partial outcomes.
4. Evidence-based adjudication, supporting finding matching, independent evaluation labels.

Upload implementation must preserve manifests/configuration/lockfiles and allow review of
excluded build folders. Validate archive sizes, traversal, symlinks and file counts before
extraction. Work from an immutable snapshot, not a mutable user directory. Do not execute
uploaded code or automatically install dependencies. The API must not run long scans inline.

## Storage

- PostgreSQL: metadata, normalized findings, status and provenance.
- SeaweedFS: source ZIPs, manifests, raw SARIF, logs.
- Worker-local scratch: extraction and CodeQL databases, disposable after retention policy.
- Git: application code, rules, migration history, manifests and small curated test fixtures.

## Deployment boundary

This is a single-user, localhost-only development setup without authentication. Ports bind
to 127.0.0.1. Before any shared deployment, implement authentication/ownership checks,
TLS, secret management, quotas and isolated scanner workers. Docker for the application
does not itself make arbitrary uploaded source safe to execute.

There is no scan POST endpoint yet, no synthetic scanner output, and no pre-labelled claim
that a missing CodeQL result proves a Semgrep finding false. The five schema tables prepare
for the next milestones; only project endpoints are exposed in this initial version.
