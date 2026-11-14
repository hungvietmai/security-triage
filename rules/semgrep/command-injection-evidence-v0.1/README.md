# CWE-78 safety-evidence rules for Semgrep CE v0.1

The scan worker runs [dead-branch.yaml](dead-branch.yaml) as the open-source adjudication step
of the `command-injection-v0.2` profile (Python). Semgrep CE is LGPL-2.1; the rules use only its
taint mode, `metavariable-comparison` and constant propagation. The profile pins the file by
SHA-256.

| Rule | Reports |
|---|---|
| `st-cmd-flow-none` | A command argument reached by data from a Flask request, a function parameter, `sys.argv`, `os.environ` or `input()`. The control rule |
| `st-cmd-flow-all` | The same, except flows that pass through an assignment in a branch that can never run |
| `st-dead-assignment` | The right-hand side of each such assignment |

A branch "can never run" when its condition is an integer comparison (`>`, `<`, `>=`, `<=`,
`==`, `!=`) that Semgrep folds to a constant: literals, arithmetic on them, and names Semgrep's
constant propagation proves constant.

## How the worker uses it (filter rule G3)

A review candidate is filtered on this evidence only when all of the following hold:

1. `st-cmd-flow-none` reports the candidate's command and `st-cmd-flow-all` does not;
2. every flow another tool reported at the call (CodeQL, a Semgrep taint rule) comes with a
   path, and each of its reported paths has a step on the line of a dead assignment;
3. CodeQL's own safety-evidence query, when the profile runs one, does not still report the flow;
4. the scan and this step completed.

Otherwise the candidate stays in the main review list with the reason recorded. Nothing is
deleted either way.

## Assumptions and limits

- **Intraprocedural.** Semgrep CE tracks data within one function. Condition 2 is what ties an
  interprocedural claim of another tool to the dead code; a flow that tool did not report as a
  path is not covered.
- **Reported paths, not all paths.** CodeQL exports a few example paths per alert. A path it
  did not export and that avoids the dead branch would not be seen.
- **Module-level names assigned once** in the file are folded as constants. A value changed from
  another module is not seen (`tests/cases.py`, `refuted_module_name_assigned_once`).
- **Sources are a fixed list.** Data entering through anything else (a global, an attribute of
  an object, a call result) is not tracked by these rules, so condition 1 says nothing about it.
- Only `if`/`else` statements with a constant integer comparison are recognized. Conditional
  expressions, string comparisons, `while` and `match` are not.

## Checks

[tests/cases.py](tests/cases.py) holds synthetic functions named `refuted_*` (the evidence rule
must drop the command) and `kept_*` (it must still report it). Run them with the pinned Semgrep:

```bash
docker compose exec -T worker python - < rules/semgrep/command-injection-evidence-v0.1/tests/check.py
```

Result on 2026-11-14 with Semgrep 1.178.0: 13/13 cases as expected.

Do not edit `dead-branch.yaml`. A new version needs a new directory and profile.
