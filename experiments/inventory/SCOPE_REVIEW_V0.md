# Scope review v0 — Linux/POSIX OS command execution

Status: **pre-scan reviewed**  
Date: 2026-10-05  
Basis: Amendment 04.

No Semgrep/CodeQL pair result was used. Verdicts were based on public advisory and fix-patch evidence collected after Amendment 04 was tagged.

## Summary

- Usable groups reviewed: **62**.
- Group-level in scope: **49**.
- Group-level out of scope: **13**.
- Mixed groups (contain both in-scope and out-of-scope pair rows): **2**.
- Reviewed pair rows: **71**.
- Source/provenance-excluded rows were not re-reviewed for scope.

### Group counts by language

| Language | In scope | Out of scope |
|---|---:|---:|
| javascript | 34 | 1 |
| python | 15 | 12 |

## Out-of-scope groups

| Group | Frozen split | Reason |
|---|---|---|
| `pyvul:ansible/ansible` | development | Reviewed fixes concern facts filtering/template unsafe preservation, not an OS process/command-execution sink. |
| `pyvul:apache/airflow` | development | Fix restricts ODBC driver configuration from connection extras; no OS process/command execution is repaired. |
| `pyvul:autogluon/autogluon` | held_out | Fix changes yaml.load to safe_load; vulnerability is unsafe deserialization. |
| `pyvul:dgilland/pydash` | development | Fix blocks dunder attribute access; vulnerable construct is object/introspection access, not OS command execution. |
| `pyvul:django/django` | development | Header/URL validation fix; no OS process/command execution sink. |
| `pyvul:google/slo-generator` | development | Fix replaces unsafe YAML loader with SafeLoader; vulnerability is unsafe deserialization. |
| `pyvul:langchain-ai/langchain` | development | Fix removes arbitrary Python exec in JIRA wrapper; no OS command sink is the vulnerable construct. |
| `pyvul:pytorch/pytorch` | held_out | Fix restricts Python eval of JIT annotation strings; vulnerable construct is language evaluation. |
| `pyvul:snowflakedb/snowflake-connector-python` | held_out | Fix validates SSO URL before opening a browser; no OS command-execution sink is repaired. |
| `pyvul:tankywoo/simiki` | held_out | Fix changes PyYAML loading behavior; vulnerability is unsafe deserialization. |
| `pyvul:tensorflow/tensorflow` | held_out | Fix replaces Python eval with literal_eval; vulnerability is language-level code evaluation. |
| `pyvul:yt-dlp/yt-dlp` | development | Fix addresses shell escaping for --exec on Windows; frozen primary threat model is Linux/POSIX. |
| `secbench:hot-formula-parser` | reserve | GHSA/fix shows the vulnerable parse path concatenates input into JavaScript eval; OS execution is only a possible payload after language-level code execution. |

## Mixed groups

### `pyvul:mlflow/mlflow`

- `pyvul-mlflow-mlflow-6dde93758d42`: **in_scope** — Fix quotes values used to construct commands executed through MLflow process/shell helpers.
- `pyvul-mlflow-mlflow-a98a341a7222`: **out_of_scope** — Fix introduces Jinja2 SandboxedEnvironment; vulnerable construct is template interpretation.
- `pyvul-mlflow-mlflow-802911381717`: **out_of_scope** — Fix introduces Jinja2 SandboxedEnvironment; vulnerable construct is template interpretation.

### `pyvul:paddlepaddle/paddle`

- `pyvul-PaddlePaddle-Paddle-c5f6862d118d`: **in_scope** — wget command is constructed and executed by subprocess.Popen(..., shell=True).
- `pyvul-PaddlePaddle-Paddle-49bec1760535`: **in_scope** — Input is concatenated into os.popen('echo -n ' + value), a shell command sink.
- `pyvul-PaddlePaddle-Paddle-5ed9478fdef9`: **out_of_scope** — Fix removes Python eval-based comparison logic; no OS command sink is the vulnerable construct.

## Aggregation rule

A repository/package group is retained in its frozen split when at least one pair row is `in_scope`. Pair rows marked `out_of_scope` are excluded from the primary detection/ranking denominator. This preserves split-v0 group membership without redrawing the held-out sample.
