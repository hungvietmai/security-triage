# Backend — agent guide

FastAPI + SQLAlchemy 2 + Alembic + Celery on Python 3.12, organized by domain
after [fastapi-best-practices](https://github.com/zhanymkanov/fastapi-best-practices)
(the backend counterpart of the frontend's bulletproof-react layout). This file
is the source of truth for how code in `backend/` is structured and written.
Product context lives in `../README.md` and `../docs/architecture.md`; research status
and rules live in `../docs/research.md`.

## Commands

Run from `backend/` with [uv](https://docs.astral.sh/uv/). Python is pinned to
3.12 by `.python-version`, matching the Docker image.

| Command | Purpose |
|---|---|
| `uv run pytest` | Tests (SQLite unless `TEST_DATABASE_URL` is set) |
| `uv run pytest --cov` | Tests with branch coverage; fails below 90 % |
| `uv run ruff check . && uv run ruff format --check .` | Lint + format check |
| `uv run ruff format .` | Format |
| `uv run mypy` | Strict type check of app/, scripts/, migrations/, tests/ |
| `uv run pip-audit` | Known-vulnerability scan of installed dependencies |
| `uv run alembic revision --autogenerate -m "..."` | New migration (review it by hand) |
| `uv run alembic check` | Fails if models and migrations differ |
| `uv run python -m scripts.export_openapi ../frontend/openapi.json` | Export the API contract for the frontend |

**Before finishing:** ruff check + format check + mypy + `pytest --cov` must pass. The
authoritative run is in Docker against PostgreSQL, from the repo root:

```bash
docker compose --profile test run --build --rm test
```

## Git hooks

Husky lives at the repository root (`../package.json`, `../.husky/`); run
`npm install` there once to enable it.

- **pre-commit** — lint-staged with `lint-staged.config.mjs`: `ruff format` and
  `ruff check --fix` on staged `.py` files, then `mypy` for the project. Hooks
  check the *staged* snapshot, so stage every file a change depends on.
- **pre-push** — `pytest --cov` here and the frontend suite.

## Project structure

```
backend/
├── app/
│   ├── main.py            # create_app(): middleware, exception handlers, /api/v1 routers
│   ├── models.py          # Model registry: imports every feature's models (Alembic, tests)
│   ├── core/              # Cross-cutting infrastructure, feature-agnostic
│   │   ├── config.py      # Settings (pydantic-settings, env vars / .env)
│   │   ├── setup.py       # Middleware (CORS) and lifespan (engine disposal)
│   │   ├── logging.py     # Formatting for app.* loggers
│   │   ├── database.py    # Base (naming convention), engine, SessionDep, get_or_raise
│   │   ├── models.py      # Identity mixin (id, created_at, updated_at), JSON_VALUE
│   │   ├── schemas.py     # InputSchema, ReadSchema, BlankToNone
│   │   ├── pagination.py  # PageParamsDep, Page[T], PageResult, paginate()
│   │   ├── sorting.py     # sort_param(), Sort, apply_sort()
│   │   ├── filtering.py   # SearchQuery (?q=), apply_search(), escape_like()
│   │   ├── exceptions.py  # AppError / NotFoundError / ConflictError, ErrorResponse
│   │   └── storage.py     # Shared S3 (SeaweedFS) client
│   ├── features/          # One package per domain — see below
│   ├── scanners/          # Semgrep/CodeQL/Bandit/ESLint adapters, scan profile, source downloads
│   ├── triage/            # Pure reconciliation, evidence, priority policy, adjudication (stdlib only)
│   ├── workflows/         # Multi-feature flows: scans/ (API, execution, persistence)
│   └── workers/           # Celery app (composition); tasks live in workflows/
├── migrations/            # Alembic; versions/NNNN_description.py
├── scripts/               # One-off CLIs: init_storage, export_openapi, check_worker, scan_families
└── tests/                 # Mirrors app/: core/, features/<f>/, cross-cutting tests at the root
```

### Features

```
app/features/<feature>/
├── router.py        # Endpoints only: parse, call service/dependencies, return schemas
├── schemas.py       # Pydantic request/response models (become the OpenAPI contract)
├── models.py        # SQLAlchemy models for this domain's tables
├── service.py       # Business logic and persistence; takes a Session, no HTTP
├── dependencies.py  # Reusable Depends(): validation such as "project exists"
├── exceptions.py    # Domain errors (subclass app.core.exceptions)
└── constants.py     # Enums/limits when needed
```

Create only the modules a feature needs. Current features: `projects`
(API: create/list/get), `health` (liveness/readiness), and model-only
`sources`, `scans`, `findings`, `triage`. Their scan API lives in
`app/workflows/scans/`, which uses the same router/service/schemas layout.

The scan worker keeps Celery registration, retries and orchestration in `task.py`.
`snapshots.py` acquires and validates source archives; `analysis.py` runs scanners
and triage for one language. `results.py` defines the data passed to `persist.py`,
which owns the transaction that replaces a scan's persisted results.
The worker runs up to `SCANNER_WORKERS` independent tools per language (default 2)
and `ARTIFACT_UPLOAD_WORKERS` streamed artifact uploads (default 4). Languages
remain sequential; standalone `run_pipeline()` calls default to sequential tools.
Record concurrency settings with scan provenance when changing execution behavior.

`classification.py` and `families.py` hold the composite (multi-family) scan: the scanners
run once, one CodeQL database is created, every finding is routed to one analysis family
before anything is merged, and each family is assessed by its member profile's existing
entry point (`scan_language`, `scan_language_evidence` or, for a family that is only
detected and kept, `detection.scan_language_detection`). A finding whose family cannot be
named stays unassigned at priority U, and findings a family could not rank are held as
units at priority U (`F10_FAMILY_NOT_RANKED`), so every finding of a composite scan sits in
exactly one unit. A single-profile scan whose profile ranked nothing (a partial
`path-traversal-v0.2` run) holds its alerts the same way through `families.hold_unranked`,
called from `task.scan_snapshot`; never leave a stored finding without a unit. A new family
filters nothing until its own evidence has been evaluated.

A composite profile (`"kind": "composite"`, `profiles/multi-cwe-v0.1/`,
`profiles/multi-cwe-v0.2/`, `profiles/multi-cwe-v0.3/`, `profiles/multi-cwe-v0.4/`,
`profiles/multi-cwe-v0.5/` and `profiles/multi-cwe-v0.6/`) pins its members' manifests;
`scanners/profile.py` loads it, `families.members_of` checks that it names families in `families.FAMILIES`, and
`task.scan_snapshot` runs it. `families.to_language_result`
turns a composite run into one `LanguageResult` with a part per family; `persist.py` writes
tool runs and findings per language and units per part, with `location_units.analysis_family`
and the finding's classification in `findings.evidence`. Reads select a composite scan's
units by scan alone (`service.result_filters`); a single-profile scan stores no family and
gets it from its profile on read (`service.scan_family`). `service.evidence_state` is the
one place that turns a filter record into what the evidence says: keep it separate from the
scan status and from `disposition`. The development CLI `scripts/scan_families.py` runs the
same composition without the database and compares it with single-profile scans. Plan,
invariants and status: `../docs/plans/multi-cwe.md`.

A `"kind": "detection"` profile (`profiles/sql-injection-v0.1/`, family `sql-injection`,
CWE-89) pins queries of the installed standard CodeQL pack by hash and the CWEs of each rule in
its manifest. It runs only as a member, in its own pass (`codeql-sql-injection`) on the shared
database, and `detection.keep_detected` makes one unit per reported location at the manifest's
tier, always in the review list. `multi-cwe-v0.1` must keep producing what
`tests/golden/composite/` records; `multi-cwe-v0.2` adds a member and changes nothing else.

A detection manifest with `"schema": 2` (`profiles/sql-injection-v0.2/`, member of
`multi-cwe-v0.3`) also runs Semgrep and Bandit, each as a member pass of its own on the same
source (`scanners/passes.py`: `semgrep-sql-injection`, `bandit-sql-injection`; SARIF, logs, staged
rules and raw IDs carry the pass name). Every Semgrep rule file is staged in its own folder
(`r<index>`), and `detection.canonical_rule_id` turns the reported ID back into the pinned file's
upstream rule ID, stored as `rule_id`; the raw ID stays in `raw_rule_id`. `units:
"sql-call-site-v1"` selects `detection.keep_detected_v2`: alerts of any tool become one unit only
when each reported region lies inside the same Python SQL execution call located by
`workflows/scans/sql_sites.py` (innermost call when calls nest, ASCII lines only); everything else
stays one unit per reported location **and tool**, and JavaScript/TypeScript has no locator yet.
Nothing is filtered. A failed or incomplete member pass makes the family's run partial: the
alerts of the other passes are still kept, with `run_incomplete`.
`units: "sql-call-site-v2"` (`profiles/sql-injection-v0.3/`, member of the experimental
`multi-cwe-v0.4`) adds one step: `sql_sites.locate_sql_strings` finds statements
`name = <string expression>` whose name is bound once in its scope and read only as the first
argument of one execution call, and `detection.link_decisions` joins a Bandit B608 alert on one of
that statement's string literals to the call's unit when the call holds a CodeQL or Semgrep alert
(mapping `explicit_link`, `linked_by` in the evidence, units `detection-units-v3`). Every other B608
keeps its own unit, with the reason. Keep the v1 path byte-identical: the new mode is opt-in.

`profiles/cross-site-scripting-v0.1/` (family `cross-site-scripting`, CWE-79, member of the
experimental `multi-cwe-v0.5`) is a schema-1 detection profile with a JavaScript configuration only:
its pass `codeql-cross-site-scripting` runs the seven standard queries under `Security/CWE-079/` on
the shared JavaScript database, one thread (two threads ran out of CodeQL's 2048 MB while
compiling), and `detection.keep_detected` keeps one unit per reported location. The Python run of a
four-family scan has three families. The other three families of `multi-cwe-v0.5` are those of
`multi-cwe-v0.4`, byte for byte; `tests/workflows/scans/test_xss_family.py` checks it.

`profiles/ssrf-v0.1/` (family `ssrf`, CWE-918, member of the experimental `multi-cwe-v0.6`) is a
schema-1 detection profile for Python and JavaScript/TypeScript: its pass `codeql-ssrf` runs the
server-side request forgery queries `py/full-ssrf` and `py/partial-ssrf` on the shared Python
database and `js/request-forgery` on the shared JavaScript database, one thread, and keeps one unit
per reported location. The queries were chosen by what they check, not by their CWE tag:
`js/client-side-request-forgery` is tagged CWE-918 too but is not in the profile. The family name is
short because the pass name is stored in `tool_runs.tool` (32 characters). The other four families
of `multi-cwe-v0.6` are those of `multi-cwe-v0.5`, byte for byte;
`tests/workflows/scans/test_ssrf_family.py` checks it.

The task's time limits and the broker's visibility timeout cover the largest profile
(`task.worst_case_seconds`); change them together. `multi-cwe-v0.6` needs 13 560 s: the soft
limit is 13 800 s, the hard limit 15 300 s and the visibility timeout 5 h
(`app/workers/celery_app.py`).

To add an analysis family: add it to `families.FAMILIES` and its profiles to
`FAMILY_OF_PROFILE`, give it a member profile, and leave it without filter conditions until
they have been evaluated for that family. Never reuse another family's filter rule.

`tests/golden/legacy/` pins what the four existing profiles produce for fixed synthetic
inputs (`tests/workflows/scans/test_legacy_golden.py`). A golden file changes only with an
intended, explained behaviour change: regenerate with `UPDATE_GOLDEN=1`, review the diff and
commit it with the change that caused it.

## Architecture rules

Enforced by `tests/test_architecture.py` and ruff (`TID252`):

1. **core → features → workflows → composition.** `app/core` never imports
   `app.features`, `app.workflows`, `app.main`, `app.models` or `app.workers`.
   Features never import `app.workflows`, `app.main`, `app.models` or `app.workers`.
2. **No cross-feature imports.** Link tables with string foreign keys
   (`ForeignKey("projects.id")`), not imports. A flow that needs several features
   (creating, running and reading scans) lives in `app/workflows/<flow>/`, which may
   import features, `app.scanners`, `app.triage` and `core`, but never the composition
   layer (`app.main`, `app.models`, `app.workers`); its Celery tasks use `shared_task`.
3. **HTTP stays in the router layer.** `service.py`, `models.py` and
   `schemas.py` never import `fastapi`/`starlette`. Services raise domain
   exceptions; `core/exceptions.py` turns them into responses.
4. **Every `features/*/models.py` is imported in `app/models.py`**, or Alembic
   autogenerate and the test schema will not see its tables.
5. **Absolute imports only** (`from app.features.projects import service`).

## Core toolkit

Use these instead of re-implementing them in a feature. Each module's docstring
shows full usage; `features/projects` is the reference implementation.

| Need | Use |
|---|---|
| Request / response models | Subclass `InputSchema` (strip, forbid extra) / `ReadSchema` (from ORM) |
| Optional text that may be blank | `Annotated[str \| None, Field(max_length=N), BlankToNone]` — **`BlankToNone` last**, or blank/None input crashes with a 500 |
| List endpoint paging | `page: PageParamsDep` → `paginate(session, stmt, page)` → `XPage.from_result(...)`, where `class XPage(Page[XRead])` |
| Sorting | `SORT_COLUMNS = {"field": Model.col}` in the service (single source) + `Annotated[Sort, Depends(sort_param(SORT_COLUMNS, default="-created_at"))]`; `apply_sort(..., tiebreaker=Model.id)` |
| Text search | `q: SearchQuery = None` + `apply_search(stmt, q, Model.a, Model.b)` (case-insensitive, wildcards escaped) |
| Load by id or 404 | `get_or_raise(session, Model, id, XNotFound)` in a dependency |
| Domain errors | Subclass `NotFoundError` / `ConflictError` / `AppError` in `exceptions.py` |

Add to `core/` only what a second feature needs or what every feature must do
the same way; one-feature helpers stay in that feature. Core code must not know
about any feature (enforced).

## Patterns

**Router** — thin; annotate with `response_model` and status codes:

```python
@router.get(
    "/{project_id}",
    response_model=ProjectRead,
    responses={404: {"model": ErrorResponse, "description": "Project not found"}},
)
def get_project(project: ProjectDep) -> Project:
    return project
```

**Dependencies** validate and load, so endpoints receive valid objects:

```python
def valid_project_id(project_id: uuid.UUID, session: SessionDep) -> Project:
    project = service.get_project(session, project_id)
    if project is None:
        raise ProjectNotFound()
    return project


ProjectDep = Annotated[Project, Depends(valid_project_id)]
```

**Service** — plain functions taking `Session` first; keyword-only options;
commit inside write operations. Return models (or `PageResult[Model]`), not dicts:

```python
def list_projects(
    session: Session, *, page: PageParams, sort: Sort, search: str | None = None
) -> PageResult[Project]:
    statement = apply_search(select(Project), search, Project.name, Project.description)
    statement = apply_sort(statement, sort, SORT_COLUMNS, tiebreaker=Project.id)
    return paginate(session, statement, page)
```

List endpoints are always sorted with a unique tiebreaker; unordered pagination
repeats or skips rows.

**Errors** — subclass `AppError`/`NotFoundError` with a class-level `detail`,
and document the status in the route with `responses={...: {"model": ErrorResponse}}`.
Never raise `HTTPException` outside routers/dependencies. Response shape is
always FastAPI's `{"detail": "..."}` (validation errors keep FastAPI's list form);
the frontend's API client relies on it.

**Endpoints are sync `def`** (SQLAlchemy sync session, run in the threadpool).
Do not mix in `async def` endpoints that call blocking code.

**Long work never runs in a request.** Scans, extraction and uploads to
processing go to Celery tasks in `app/workers/`; the API records state and returns.

## Database and migrations

- Tables use the `Identity` mixin (UUID `id`, `created_at`, `updated_at`).
- Status columns are strings with `CheckConstraint`s naming each allowed value;
  name every constraint (`ck_…`, `uq_…`).
- Children cascade on delete down project → snapshot → scan → tool_run → finding.
- Migrations are immutable once merged: add a new `NNNN_description.py`
  (`revision = "NNNN"`), never edit an old one. Autogenerate, then review:
  server defaults, constraint names and downgrade must be correct.
- `alembic check` and a downgrade → upgrade round trip run in CI.

## API contract

- Every endpoint returns a Pydantic schema (not dicts or `JSONResponse`), so
  OpenAPI describes it. Document non-2xx bodies with `responses=`.
- After any change to routes or schemas, re-export `frontend/openapi.json`
  (command above) and run `npm run gen:api` in `frontend/`. CI fails if
  `openapi.json` differs from the running API.
- Paths live under `/api/v1`; keep changes backward compatible or update the
  frontend in the same change.

## Testing

- Integration first: call endpoints through the `client` fixture; use the
  `session` fixture for database-level tests. Both share one isolated database
  (`engine` fixture): a fresh PostgreSQL schema in Docker/CI, in-memory SQLite locally.
- Keep all tests under `tests/`, grouped by feature/workflow; do not put tests
  beside implementation modules. Prefer endpoint and persistence integration
  tests over mocking services/internal methods.
- Add unit tests only for necessary pure algorithm edge cases or complex boundary
  rules that integration tests cannot cover clearly; avoid implementation-mirroring
  assertions and duplicated workflow tests.
- Test behaviour, including error bodies (`{"detail": "Project not found"}`).
- Patch external systems at the service module boundary
  (`monkeypatch.setattr(service, "get_s3_client", ...)`); use botocore `Stubber`
  for S3 call shapes. Never reach real Redis/S3 from unit tests.
- File layout mirrors `app/` (`tests/features/projects/test_router.py`).
  Basenames may repeat (pytest runs with `--import-mode=importlib`).

## Security and research rules

- Treat uploaded source as hostile: never execute it or install its
  dependencies; validate archive size, file count, path traversal and symlinks
  before extraction; call scanners with argument lists, never a shell string.
- Do not report fake scan success or synthetic findings. A missing CodeQL
  result does not prove a Semgrep finding false. Keep tool output, triage
  decisions and evaluation labels separate (see `docs/architecture.md`).
- Configuration comes from environment variables via `core/config.py`; the
  defaults are local development values only. Never log secrets.
- Log with `logging.getLogger(__name__)`; `core/logging.py` formats every
  `app.*` logger (level from `LOG_LEVEL`). Use `logger.exception` in `except`
  blocks that swallow errors, as the readiness probes do.

## Conventions

- Modules and packages `snake_case`; classes `PascalCase`; functions and
  variables `snake_case`; constants `UPPER_SNAKE_CASE`.
- Schema names: `<Entity>Create`, `<Entity>Read`, `<Entity>Page`.
- Type hints everywhere; `mypy --strict` (pydantic plugin) must pass. Tests may
  leave fixtures unannotated. Type-only imports from stub packages
  (`types-boto3`, `celery-types`) go under `if TYPE_CHECKING:` — they are dev-only.
- Annotate `@contextmanager` / `@asynccontextmanager` functions as returning
  `Generator[T]` / `AsyncGenerator[T]`; `Iterator` / `AsyncIterator` is deprecated
  (Pylance flags it).
- Don't reach into another module's imports in tests (`service.Redis`); patch
  the real object (`Redis.from_url`, `time.sleep`).
- Line length 100 (ruff).
- Pass `encoding="utf-8"` to every text-mode `open`, `read_text`, `write_text` and
  `subprocess` call (`text=True`). The default is the locale encoding, which is
  cp1252 on Windows and corrupts non-ASCII source, scanner output and reasons.
- Comments explain *why*. Docstrings on modules and non-obvious functions.

## Adding a feature (checklist)

1. `app/features/<f>/models.py` + register it in `app/models.py`.
2. Migration: `alembic revision --autogenerate`, review, `alembic check`.
3. `schemas.py`, `service.py`, `exceptions.py`, `dependencies.py`, `router.py`.
4. Include the router in `create_app()` (`app/main.py`).
5. Tests in `tests/features/<f>/`; all checks pass.
6. Re-export `frontend/openapi.json` and regenerate frontend types.
