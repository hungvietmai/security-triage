# Semgrep rules

This folder holds the **evidence rule packs** the scan worker runs in its adjudication step.
Their results are evidence about existing alerts, never alerts of their own.

| Pack | Used by | What it shows |
|---|---|---|
| [command-injection-evidence-v0.1/](command-injection-evidence-v0.1/README.md) | `command-injection-v0.2` and `-v0.3`, Python, filter rule G3 | Request data reaches a command only through an assignment in a branch that never runs |
| [command-injection-evidence-js-v0.1/](command-injection-evidence-js-v0.1/README.md) | `command-injection-v0.3`, JavaScript/TypeScript, filter rule G4 | The command string of an `exec`/`execSync` call is a compile-time constant |

Each pack is pinned by SHA-256 in the profile that uses it and has synthetic cases with a check
script under `tests/`. Do not edit a pack; a new version needs a new directory and profile.

Detection and locator rules live elsewhere, versioned with the research that pins them:

- `experiments/rules/batch-01/` (JavaScript) and `experiments/rules/python-upstream/` (Python):
  the eight unchanged upstream CWE-78 rules of the `command-injection-*` profiles.
- `experiments/locators/sink-locator-v0-javascript.yaml` and `sink-locator-v1-javascript.yaml`:
  the rules that locate `child_process` calls for merging. v1 (profile v0.3) contains every v0
  rule and adds two-step aliases, destructuring, promisified functions, inline `require` and
  the `node:` prefix; `experiments/locators/check_sink_locator_v1.py` checks its 19 cases.
- `experiments/rules/`: the upstream `detect-child-process` copy and its direct-alias
  development variant (see `experiments/rules/README.md`).
- `experiments/owasp-bp-pilot/semgrep_rules.json`: the 61 community Python rules used as a
  control in the CWE-22 study.
