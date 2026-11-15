# CWE-78 constant-command evidence for JavaScript/TypeScript, Semgrep CE v0.1

The scan worker runs [constant-command.yaml](constant-command.yaml) as the adjudication step of
the `command-injection-v0.3` profile for JavaScript and TypeScript. Semgrep CE is LGPL-2.1; the
rule uses only pattern matching with constant propagation. The profile pins the file by SHA-256.

| Rule | Reports |
|---|---|
| `st-js-constant-command` | A call named `exec` or `execSync` whose first argument Semgrep proves to be a compile-time constant string: a literal, a concatenation of constants, a template without placeholders, or a variable that only ever holds constants |

The rule is evidence, never an alert: its results carry the tool name `semgrep-evidence` and are
not merged into review candidates.

## How the worker uses it (filter rule G4)

A review candidate is filtered on this evidence only when all of the following hold:

1. every call of the candidate is `child_process.exec` or `child_process.execSync`, located by
   the sink locator, so the first argument is the whole shell command;
2. this rule reports **exactly the span of that call**; a match on a call around it or inside
   it does not count;
3. no tool claims a data flow to the command (a CodeQL alert, or a Semgrep rule of the flow
   family);
4. the scan and this step completed.

Otherwise the candidate stays in the main review list with the reason recorded. Nothing is
deleted either way. The rule also matches calls that are not `child_process` (`regex.exec("a")`);
condition 1 makes those irrelevant.

## Assumptions and limits

- **Intraprocedural constant propagation.** A variable counts as constant when Semgrep sees only
  constant assignments to it. The cases in `tests/cases.js` include a module variable changed by
  another function and a variable changed inside a closure; Semgrep does not report those.
  This is tested behaviour of Semgrep 1.178.0, not a formal guarantee.
- **Only shell-string calls.** With `spawn`, `execFile` or `fork` a constant program still takes
  arguments, so the rule is not used for them.
- **A constant command is not a safe command.** The rule says the command string cannot be
  influenced through this argument. It says nothing about options such as `cwd` or `env`.
- Calls through an alias with another name (`const run = cp.exec; run("ls")`) are not reported
  by this rule and are therefore never filtered.

## Checks

[tests/cases.js](tests/cases.js) holds synthetic functions named `constant_*` (the rule must
report the call) and `kept_*` (it must not). Run them with the pinned Semgrep:

```bash
docker compose exec -T worker python - \
  < rules/semgrep/command-injection-evidence-js-v0.1/tests/check.py
```

Result on 2026-11-15 with Semgrep 1.178.0: 20/20 cases as expected (6 constant, 14 kept).

Do not edit `constant-command.yaml`. A new version needs a new directory and profile.
