# Frontend — agent guide

React 19 + TypeScript (strict) + Vite, organized after
[bulletproof-react](https://github.com/alan2207/bulletproof-react). This file is
the source of truth for how code in `frontend/` is structured and written.
Product context and backend scope live in `../README.md` and `../docs/architecture.md`.

## Commands

Run from `frontend/`. Node 24.

| Command                           | Purpose                                                                                          |
| --------------------------------- | ------------------------------------------------------------------------------------------------ |
| `npm run dev`                     | Vite dev server on :5173; proxies `/api` to `API_PROXY_TARGET` (default `http://localhost:8000`) |
| `npm run check`                   | typecheck + lint + format check + tests. **Run before finishing any change.**                    |
| `npm test` / `npm run test:watch` | Vitest (jsdom)                                                                                   |
| `npm run format`                  | Prettier, including Tailwind class sorting                                                       |
| `npm run build`                   | Type-check and production build                                                                  |
| `npm run gen:api`                 | Regenerate `src/types/api-schema.d.ts` from `openapi.json`                                       |

Whole stack: `docker compose -f compose.yaml -f compose.dev.yaml up --build -d`
from the repo root (FE with HMR on :5173).

## Project structure

```
src/
├── app/                 # Application layer
│   ├── index.tsx        # <App/>: creates QueryClient + router
│   ├── provider.tsx     # ErrorBoundary, theme, React Query, tooltips, toaster
│   ├── router.tsx       # Route tree, search validation, loaders
│   └── routes/          # One file per route; composes features. Tests sit beside them.
├── components/          # Shared, feature-agnostic UI
│   ├── ui/              # shadcn/ui (generated; see "UI components")
│   ├── layouts/         # App shell: sidebar, header, breadcrumbs, theme toggle
│   ├── errors/          # Error boundary and route error fallbacks
│   └── common/          # Page header, query error, pagination, "not implemented", …
├── config/              # env.ts (validated VITE_APP_* vars), paths.ts (route paths/labels)
├── features/            # Feature modules — see below
├── hooks/               # Shared hooks
├── lib/                 # Preconfigured libraries: api-client.ts, react-query.ts, utils.ts (cn)
├── testing/             # test-utils, setup, MSW mocks, architecture test
├── types/               # api-schema.d.ts (generated), api.ts, router.ts (route typing)
└── utils/               # Shared pure helpers (format.ts)
```

### Features

Each feature is self-contained. Create only the folders you need:

```
src/features/<feature>/
├── api/         # One file per endpoint: fetcher + queryOptions + hook
├── components/  # Feature components
├── hooks/       # Feature hooks that are not API hooks
├── stores/      # Feature client state (only if really needed)
├── types/       # Feature types and constants (index.ts)
└── utils/       # Feature helpers
```

Current features: `projects` (list, detail, create) and `health` (readiness/liveness).

## Architecture rules

These are enforced by `src/testing/architecture.test.ts`; `npm test` fails on a violation.

1. **Unidirectional flow: shared → features → app.**
   `components`, `config`, `hooks`, `lib`, `types`, `utils` never import from
   `@/features/*` or `@/app/*`. Features never import from `@/app/*`.
2. **No cross-feature imports.** `features/a` never imports `features/b`.
   Compose features in `app/routes/*` instead. If a shared layout needs
   feature UI, pass it in as a slot — see `DashboardLayout`'s `sidebarFooter`,
   which `app/routes/root.tsx` fills with `health`'s `SystemStatusIndicator`.
3. **Absolute imports.** Always `@/…`; never relative (`./`, `../`).
4. **Production code never imports `@/testing`**, except the dev-only MSW
   bootstrap in `main.tsx`.
5. **Colocate.** Code used by one feature lives in that feature; code used by one
   route lives in or next to that route file. Promote to shared only on second use.

## API layer

- All HTTP goes through `@/lib/api-client` (`api.get`, `api.post`). It adds the
  `/api/v1` prefix from `env.API_URL`, a 15 s timeout, JSON handling, and turns
  every failure into `ApiError` (`status` 0 = network). FastAPI `detail`
  messages (string or validation list) become the error message.
- **Types come from the backend.** Never hand-write response types; use
  `Schemas["ProjectRead"]` from `@/types/api`, re-exported as feature types
  (`features/projects/types`). After backend schema changes:

  ```bash
  cd backend && uv run python -m scripts.export_openapi ../frontend/openapi.json
  cd ../frontend && npm run gen:api
  ```

  CI fails if `openapi.json` differs from the running API or
  `api-schema.d.ts` differs from `openapi.json`.

- **One file per endpoint** in `features/<f>/api/`, named `get-x.ts`,
  `create-x.ts`, …, exporting:

  ```ts
  // features/projects/api/get-project.ts
  export function getProject(projectId: string, signal?: AbortSignal) {
    return api.get<Project>(`/projects/${encodeURIComponent(projectId)}`, {
      signal,
    });
  }

  export function getProjectQueryOptions(projectId: string) {
    return queryOptions({
      queryKey: ["projects", "detail", projectId],
      queryFn: ({ signal }) => getProject(projectId, signal),
    });
  }

  export function useProject({
    projectId,
    queryConfig,
  }: {
    projectId: string;
    queryConfig?: QueryConfig<typeof getProjectQueryOptions>;
  }) {
    return useQuery({ ...getProjectQueryOptions(projectId), ...queryConfig });
  }
  ```

  Mutations export the zod input schema, the fetcher, and
  `useX({ mutationConfig })` that updates or invalidates affected queries (see
  `create-project.ts`). Pass `signal` through so navigation cancels requests.

- Query keys: `[feature, "list" | "detail", params]`. Invalidate by prefix.
- Route loaders in `app/router.tsx` only _start_ fetches
  (`void queryClient.prefetchQuery(getXQueryOptions(...))`); they never await.
  Components own pending and error UI.

## State

- Server state: TanStack Query only. Never copy query data into `useState`.
- URL state: pagination, tabs and filters live in validated search params
  (`app/routes/**/search.ts`, zod with `.catch()` defaults) so links and reloads work.
- Component state: `useState` / `useReducer`. Lift only when siblings need it.
- Forms: React Hook Form + zod (`zodResolver`), fields built with shadcn `Field`
  components and `Controller`; see `create-project-dialog.tsx`.
- Theme: `next-themes`.
- **No global client-state library yet.** Zustand is the planned choice when
  state must be shared across features; do not add it before that need exists.

## Error handling

- Queries render errors in place with `QueryError` (with retry). A 404 gets its
  own "not found" state (`isApiError(error, 404)`).
- Mutations: the `MutationCache` in `lib/react-query.ts` toasts `error.message`.
  When a component shows the error itself (e.g. inside a form), set
  `meta: { handlesError: true }` so the user does not see it twice.
- Queries do not retry 4xx; transient failures retry twice.
- Render errors: `RouteErrorFallback` per route (router `defaultErrorComponent`);
  `MainErrorFallback` via `react-error-boundary` around the whole app.

## UI components

- shadcn/ui (`radix-nova` style, Radix primitives, lucide icons) lives in
  `components/ui/`. Add components with `npx shadcn@latest add <name>` rather
  than writing them by hand. Treat these files as vendored: adjust via
  `className` at the call site; edit the file only for a deliberate app-wide change.
- Tailwind CSS v4 only; no CSS modules or inline style objects. Use theme tokens
  (`text-muted-foreground`, `bg-card`, …) so light and dark mode both work.
  Merge classes with `cn()` from `@/lib/utils`.
- Composition over props: prefer `children`/slots to boolean or render props.
  Split a component when it has more than one job or a JSX block needs a name.
- Page files use `PageHeader` + content; page-level empty states use
  `<Empty className="flex-none …">` so they do not stretch to full height.
- Accessibility: every control has an accessible name; icon-only buttons get
  `aria-label`. `SidebarInset` already renders `<main>` — do not add another.

## Product honesty

The backend only supports projects and health checks today. For anything else
(sources, scans, findings, adjudication) show `NotImplemented` or "—" with an
explanation. **Never render sample, placeholder or fake scan data**, and never
imply a missing CodeQL result proves code safe. MSW mock data exists only in
tests and the opt-in dev mock mode.

## Testing

- **Integration first.** Render the real app at a URL with `renderApp(path)`
  from `@/testing/test-utils` — real router, providers and API client — and
  assert what the user sees. Scope queries with `mainContent()` to skip the sidebar.
- **MSW for HTTP**, never mock `fetch` or modules. Default handlers in
  `testing/mocks/handlers/*` serve the in-memory `db` (reset before each test);
  seed with `db.projects = [makeProject({...})]`. Override per test with
  `server.use(http.get(...))`. Unhandled requests fail the test.
- Unit tests for shared logic (`lib/`, `utils/`) beside the file.
- Query by role and label, interact with `user` from `renderApp`, and await
  `findBy*`/`waitFor` for anything async.
- Test files: `*.test.ts(x)` next to the code. Architecture rules live in
  `testing/architecture.test.ts`.
- Dev mock mode: `VITE_APP_ENABLE_API_MOCKING=true npm run dev` answers API
  calls in the browser with the same handlers (dev builds only).

## Git hooks

Husky lives at the repository root (`../package.json`, `../.husky/`); run
`npm install` there once to enable it.

- **pre-commit** — lint-staged with `lint-staged.config.js`: Prettier and oxlint on
  staged files, then `tsc -b` for the project. `openapi.json` is excluded via
  `.prettierignore` (it must stay byte-identical to the backend export).
- **pre-push** — `npm test` here and the backend suite.

Fix the cause instead of bypassing with `--no-verify`.

## Conventions

- Files and folders: `kebab-case` (`project-details.tsx`, `use-mobile.ts`).
- Components `PascalCase`; functions and variables `camelCase`; constants `UPPER_SNAKE_CASE`.
- Route components are named `XRoute` and exported by name for `lazyRouteComponent`.
- A component file exports components only (Fast Refresh); put constants,
  hooks and helpers in `types/`, `hooks/` or `utils/`.
- UI text is Vietnamese; code, comments and identifiers are English.
- Comments explain _why_, not what.
- Environment variables must be `VITE_APP_*` and declared in `config/env.ts`.
  Never put secrets or backend credentials in the frontend.
- Keep `lint` (oxlint) and `format` (Prettier) clean; do not disable rules inline
  without a comment explaining why.

## Adding a feature (checklist)

1. Backend endpoint exists → regenerate types (`gen:api`).
2. `features/<f>/types/index.ts` re-exports the generated types and constants.
3. `features/<f>/api/<verb>-<noun>.ts` per endpoint (fetcher, queryOptions, hook).
4. Feature components in `features/<f>/components/`.
5. MSW handlers in `testing/mocks/handlers/<f>.ts`, registered in `handlers/index.ts`.
6. Route file in `app/routes/`, registered in `app/router.tsx` with a
   `staticData.crumb`, path/label in `config/paths.ts`, nav entry in
   `components/layouts/app-sidebar.tsx` if it is top-level.
7. Integration test beside the route; `npm run check` passes.

## Not adopted (yet)

Deliberately absent for a local, single-user tool without auth: global state
library, auth/token refresh, Sentry, CDN deploy config, Storybook, Plop,
DOMPurify (no raw HTML is rendered — keep it that way), E2E tests
(Playwright is the planned tool). Add one only with a concrete need.
