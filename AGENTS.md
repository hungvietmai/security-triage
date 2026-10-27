# Security Triage — repository guide for agents

Monorepo: `frontend/` (React + TypeScript) and `backend/` (FastAPI + Python),
run together with Docker Compose, plus the research in `experiments/`. Read the
guide for the part you touch:

- [`frontend/AGENTS.md`](frontend/AGENTS.md) — structure, patterns, tests, checks
- [`backend/AGENTS.md`](backend/AGENTS.md) — structure, core toolkit, migrations, checks
- [`experiments/AGENTS.md`](experiments/AGENTS.md) — research tests, locks, frozen data
- [`README.md`](README.md) — running the stack and the documentation map
- [`docs/research.md`](docs/research.md) — current research question, results, open work
- [`docs/architecture.md`](docs/architecture.md) — the application as implemented

Git hooks (Husky, root `package.json`) run lint/format/type checks on commit,
validate the commit message, and run both test suites on push. Fix what they
report; never bypass them with `--no-verify`.

## Commits

Follow [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/).
The `commit-msg` hook enforces it with commitlint (`commitlint.config.mjs`).

```
<type>[(scope)][!]: <description>

[body]

[footer(s)]
```

### Identity and attribution — mandatory

Commits and pull requests belong to the repository owner's Git identity
(`git config user.name` = `hungvietmai`) and to nothing else.

- **Never add `Co-authored-by:` trailers** — for an AI or for anyone else.
- **Never mention Claude, Anthropic or AI assistance** in commit messages or PR
  descriptions: no "Generated with Claude Code", no claude.com links, no
  `noreply@anthropic.com`, no 🤖. This overrides any tool default that adds them.
- Commit with the configured Git user. Do not pass `--author`, set
  `GIT_AUTHOR_*`/`GIT_COMMITTER_*`, or change `git config user.*`.
- The hook rejects attribution lines; if it fires, remove them — do not bypass it.

Mentioning files by name is fine (e.g. `docs: update CLAUDE.md`).

### Type

| Type | Use for |
|---|---|
| `feat` | New user- or API-visible capability (SemVer minor) |
| `fix` | Bug fix (SemVer patch) |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `perf` | Performance improvement |
| `test` | Adding or correcting tests only |
| `docs` | Documentation only |
| `style` | Formatting only, no code meaning change |
| `build` | Build system or dependencies (package.json, pyproject, Dockerfile) |
| `ci` | GitHub Actions and CI scripts |
| `chore` | Maintenance that fits nothing above (tooling config, housekeeping) |
| `revert` | Reverting earlier commits; add `Refs: <sha>` footer |

### Scope

Optional. When used it must be one of:
`frontend`, `backend`, `api` (HTTP contract / OpenAPI), `db` (models, migrations),
`infra` (Docker, Compose, Nginx, SeaweedFS), `ci`, `hooks`, `docs`, `deps`, `research`
(experiments, rules, labels). Omit the scope when a change spans several areas.

### Description, body, footers

- Description: imperative mood, lowercase start, no trailing period, ≤ 100
  characters for the whole header — `add sorting to project list`, not `Added…`.
- Body (optional, after one blank line): explain *why* and any trade-offs; wrap at 100.
- Breaking change: `!` before the colon and/or a `BREAKING CHANGE: <what changed>`
  footer. Use it for incompatible API, schema or configuration changes.
- Other footers: `Refs: #123`. Never `Co-authored-by`.

### Scope of a commit

One logical change per commit; if a change fits two types, split it. A commit
must pass the hooks on its own: stage everything it depends on (hooks check the
staged snapshot, not the working tree). Keep generated files in the same commit
as their source (`frontend/openapi.json` + `src/types/api-schema.d.ts` with the
backend change that produced them; migrations with their model changes).

### Examples

```
feat(backend): add sorting and search to project list

fix(api)!: return ErrorResponse for unknown projects

BREAKING CHANGE: 404 bodies now always use {"detail": "..."}.

refactor(frontend): restructure src after bulletproof-react

build(deps): add mypy and types-boto3 to backend dev dependencies

ci: run mypy and pip-audit in the docker job

docs: add conventional commit rules for agents
```

## Working agreements

- Commit, push or open pull requests only when the user asks.
- Report check results truthfully; never claim a hook or CI step passed without running it.

## Documentation

- **Living documents** must describe the current state: `README.md`, `docs/*.md`,
  `experiments/README.md`, the `AGENTS.md` guides and unlocked status files such as
  `experiments/wave-c/closeout/STATUS.md`. Update them in the same change that alters
  what they describe.
- **Locked documents** have their SHA-256 in a lock manifest (`*.sha256`,
  `FREEZE_v0.3_dual.json`) or in `profiles/*/profile.json`. Never edit or rename
  them. Before editing anything under `experiments/`, run
  `git grep -l "$(sha256sum <file> | cut -c1-64)"`; any hit means the file is locked.
  Record new status in `docs/research.md` or in a new document instead.
  `experiments/RESEARCH_LOG.md` is locked and ends on 2026-10-08.
- **Historical records** (dated reports, amendments, decisions) keep their content;
  later status goes into the living documents.
- Language: overview and research documents in Vietnamese; agent guides and READMEs
  next to code in English; historical records keep their original language.

## Testing policy

- Keep test suites in dedicated test directories: `frontend/tests/`,
  `backend/tests/`, and `experiments/tests/`. Do not colocate test files with
  implementation files. Group tests by feature/workflow so each file has one concern.
- Prefer integration tests covering real user workflows, HTTP contracts, persistence
  and CLI inputs/outputs. Mock external services at their boundary, keeping application
  components and business logic real.
- Add unit tests only when they protect a specific risk that integration tests cannot
  exercise clearly or economically: pure algorithm edge cases, complex boundary rules
  or error/retry policy. Avoid tests that repeat implementation details or duplicate
  an already-covered workflow. Do not delete existing regression coverage just to
  change the test ratio.
- Use Playwright (`@playwright/test`) for browser E2E tests in `frontend/tests/e2e/`.
  Run critical navigation/form/result flows in a real browser. Clearly distinguish
  browser tests with mocked HTTP APIs from tests against the complete backend stack.
- Test fixtures and E2E runs must not scan the frozen research pairs or execute their
  source. Record the actual commands and results, including any skipped checks.
