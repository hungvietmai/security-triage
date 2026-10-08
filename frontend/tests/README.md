# Tests

All frontend test suites live here, separate from application source:

- `integration/`: real app/router/providers/API client with MSW at the HTTP
  boundary. Group user workflows by feature. Polling is exercised on the scan
  page rather than on an isolated query observer.
- `unit/`: focused format and error/retry policy regressions that are useful
  independently of browser workflows. Add isolated tests only for a concrete
  algorithm or boundary risk, not to mirror implementation details.
- `e2e/`: critical workflows in Chromium through Playwright. These use HTTP
  fixtures and do **not** invoke the backend/worker/scanners. They cover actual
  browser navigation, URL reload, shadcn controls, polling and evidence sheets.
- `support/`: shared setup/helpers. Use `@test/` for imports from here and `@/`
  for application imports. Shared fixtures used by opt-in development MSW remain
  under `src/testing/mocks/`; the MSW Node server lives here.
- `architecture.test.ts`: verifies production import boundaries and prevents
  test suites from returning to `src/`.

From `frontend/`:

```powershell
npm run check               # typecheck, lint, formatting, integration + necessary unit tests
npm run test:e2e:install    # download Chromium once per Playwright version
npm run test:e2e            # browser workflows; starts Vite on 127.0.0.1:5174
npm run test:e2e:ui         # interactive local runner
npm run test:e2e:report     # open the retained HTML report
```

E2E failures retain traces and screenshots in ignored `test-results/` and
`playwright-report/` directories. CI installs browser system dependencies and
runs E2E separately from Vitest. A complete-stack backend/worker E2E validation
must be named and reported separately; these browser tests cannot establish it.
