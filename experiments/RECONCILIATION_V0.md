# Reconciliation v0 — canonical source-unit mapping

- Reconciliation version: **`reconcile-v0`**
- Sink locator version: **`sink-locator-v0`**
- Status: **frozen for development implementation**
- Scope: normalized Semgrep/CodeQL findings for Python and JavaScript command-execution sinks
- Ordering rule: the matcher applies the rules in Section 6 in order and stops at the first rule that produces one unambiguous unit.

This document freezes the source-location reconciliation rules before the
implementation in `backend/app/triage/` is written. It operationalizes the
canonical identity and fallback requirements in `EVALUATION_PROTOCOL.md` and
the application-centered pipeline in Amendment 02.

The implementation is post-processing only. It must not execute scanners, call
external processes, access a database, fetch source code, inspect a vulnerability
patch, or use held-out labels.

## 1. Package boundary

Scanner execution remains in:

```text
backend/app/scanners/
```

Result processing belongs in:

```text
backend/app/triage/
```

The triage package is reusable by both the experiment CLI and application
workers. It may import only the Python standard library and other
`app.triage.*` modules.

For reconciliation, the core merge function is pure. Its logical inputs are:

1. normalized findings;
2. located sinks;
3. source-file contents.

Its output is a deterministic collection of reconciled units plus per-finding
mapping records. It does not invoke Semgrep or CodeQL and does not read global
configuration or application state.

Sink discovery is a separate adapter step. Python sink discovery is implemented
with the standard-library `ast` module. JavaScript sink discovery is implemented
by a separately versioned repository-owned Semgrep locator ruleset. The pure
reconciler consumes the resulting sink records and does not know how they were
produced.

## 2. Canonical sink unit

The canonical sink-unit identity follows the base protocol:

```text
snapshot_sha256 + normalized_relative_path + sink_span + argument_role
```

The identity fields are:

```json
{
  "snapshot_sha256": "<sha256>",
  "path": "<normalized-relative-path>",
  "sink_span": {
    "startLine": 1,
    "startColumn": 1,
    "endLine": 1,
    "endColumn": 1
  },
  "argument_role": "shell_command | executable | argument_list | null"
}
```

`unit_id` is the SHA-256 hex digest of the UTF-8 bytes of this identity encoded
as canonical JSON with sorted keys and compact separators
(`json.dumps(identity, sort_keys=True, separators=(",", ":"))`).

CWE is not part of the unit identity. Tool identity is not part of the unit
identity. Multiple source-to-sink paths or multiple tool findings that resolve to
the same identity map to the same unit.

A sink whose call site is known but whose argument role cannot be resolved still
has a canonical identity with `argument_role = null`; its mapping status is
`role_unresolved`.

## 3. Sink record v0

A locator emits sink records before finding reconciliation. Each record contains
at minimum:

```json
{
  "path": "<normalized-relative-path>",
  "sink_span": {
    "startLine": 1,
    "startColumn": 1,
    "endLine": 1,
    "endColumn": 1
  },
  "callee": "<normalized-callee-name>",
  "argument_roles": [
    {
      "role": "shell_command | executable | argument_list | null",
      "span": {
        "startLine": 1,
        "startColumn": 1,
        "endLine": 1,
        "endColumn": 1
      }
    }
  ],
  "locator_version": "sink-locator-v0"
}
```

The `sink_span` is the complete call-expression span. Argument spans are
evidence used to infer `argument_role`; the canonical unit remains keyed by the
call `sink_span` plus the resolved role.

A single call may therefore yield more than one canonical unit when the API has
distinct executable and argument-list roles.

## 4. Sink locator v0

### 4.1 Python — standard-library AST

Python sink discovery uses only `ast`. It must recognize direct imports and
aliases, including forms such as:

```python
import subprocess as sp
sp.run(...)

from os import system
system(...)
```

The locator recognizes these command/process execution families:

- `os.system`
- `os.popen`
- `os.exec*`
- `os.spawn*`
- `subprocess.*`
- `asyncio.create_subprocess_exec`
- `asyncio.create_subprocess_shell`
- `pty.spawn`

Alias resolution is lexical and import-based in v0. The locator must not infer
arbitrary runtime rebinding, monkey patching, dynamic imports, or reflection.

### 4.2 JavaScript — repository-owned Semgrep locator rules

JavaScript uses a dedicated **sink-location** Semgrep ruleset stored in the
repository and versioned as `sink-locator-v0`. It is not downloaded at runtime.

The ruleset locates the following `child_process` calls:

- `exec`
- `execSync`
- `spawn`
- `spawnSync`
- `execFile`
- `execFileSync`
- `fork`

It must cover ordinary imports/requires and aliases, including the alias form
already observed in the curling development case.

It also locates:

- `shelljs.exec`

The JavaScript locator is an acquisition step for sink metadata only. Its output
is converted into the same sink-record schema as the Python AST locator before
calling the pure reconciler.

Unit tests for reconciliation consume recorded locator output. A workflow/Docker
integration test may execute the pinned real Semgrep binary against locator
fixtures.

## 5. Argument-role table v0

Argument roles describe the security-relevant semantic position at a sink. The
table below is frozen for `reconcile-v0`.

| Sink/API family | Condition | Role assignment |
|---|---|---|
| JavaScript `child_process.exec`, `execSync` | any | argument 0 = `shell_command` |
| `os.system`, `os.popen` | any | argument 0 = `shell_command` |
| `asyncio.create_subprocess_shell` | any | argument 0 = `shell_command` |
| `shelljs.exec` | any | argument 0 = `shell_command` |
| JavaScript `spawn`, `spawnSync`, `execFile`, `execFileSync`, `fork` | no `{shell: true}` | argument 0 = `executable`; argument 1 = `argument_list` when present |
| JavaScript `spawn`, `spawnSync`, `execFile`, `execFileSync` | options resolve syntactically to `{shell: true}` | argument 0 = `shell_command` |
| Python `subprocess.*` | `shell=True` is syntactically explicit | first command/args argument = `shell_command` |
| Python `subprocess.*` | list/tuple command form without `shell=True` | element 0 of the command sequence = `executable`; remaining command sequence = `argument_list` |
| `asyncio.create_subprocess_exec` | any | argument 0 = `executable`; remaining positional arguments = `argument_list` |
| `os.exec*`, `os.spawn*` | direct process-exec form | executable/program position = `executable`; remaining argv position(s) = `argument_list` |
| `pty.spawn` | argv sequence can be resolved syntactically | element 0 = `executable`; remaining sequence = `argument_list` |

Only syntactically explicit `shell=True` / `{shell: true}` changes the v0
role assignment. V0 does not evaluate arbitrary variables, object spreading,
constant propagation, helper-return values, or dynamic option construction to
prove shell mode.

If the sink call is recognized but the relevant role cannot be assigned
unambiguously, `argument_role` is `null` and the mapping status is
`role_unresolved`. The finding is retained.

## 6. Finding-to-sink reconciliation

The reconciler evaluates the following rules **in this exact order** and stops at
the first rule that produces one unambiguous mapping.

All path comparisons use normalized repository-relative paths. A candidate sink
must be in the same normalized path as the source location being compared.

### Rule 1 — explicit CodeQL link

If a CodeQL finding message contains a link of the form:

```text
[shell command](n)
```

then resolve `n` against the finding's SARIF `relatedLocations`.

This reuses the narrow evidence logic already prototyped by `propose()` in
`experiments/build_review.py`:

1. the referenced related-location ID must resolve exactly once;
2. its source path and region must be valid;
3. the related-location region must fall within exactly one located sink;
4. if nested sinks contain the region, choose the unique innermost sink;
5. the sink must yield one applicable argument role under Section 5.

If those conditions hold, map the finding to that unit with mapping method
`explicit_link`.

If the link itself is ambiguous, malformed, points outside source, intersects
multiple incomparable sinks, or does not establish one role, this rule does not
silently guess. Continue only when the next rule can operate on the finding's
primary location; otherwise retain a fallback unit with the appropriate review
status.

### Rule 2 — strict containment

Compare the finding's **primary reported region** with located sink call spans in
the same file.

A sink is a containment candidate only when the finding region is **strictly
inside** the sink call span; exact span equality is excluded here so Rule 3
remains reachable.

If exactly one candidate exists, map to it.

If candidates are nested, choose the unique innermost call: the candidate whose
span is contained by every other containing candidate. Equivalently, it is the
smallest enclosing call span under source order.

If two or more incomparable sinks contain the finding region, the mapping is
ambiguous and no containment mapping is produced.

Successful status/method: `mapped` / `containment`.

### Rule 3 — exact span match

If the finding's primary region is exactly equal to one located sink
`sink_span`, map to that sink.

If more than one sink record has that exact span and role resolution cannot make
the target unique, do not choose based on locator order.

Successful status/method: `mapped` / `exact_span`.

### Rule 4 — fallback

A finding that is not mapped by Rules 1–3 is never discarded.

For a finding with a usable source path and reported region, create a fallback
identity from:

```text
snapshot_sha256 + normalized_relative_path + reported_region
```

and set:

```text
mapping_status = unmapped
argument_role = null
```

The fallback `unit_id` is the SHA-256 digest of the canonical-JSON fallback
identity using the same serialization rule as Section 2.

When the path or region is missing, the protocol's fallback-discriminator rule
still applies: include the preserved raw finding identity (for example
`raw_id` / run-result identity) as a discriminator so unrelated unlocated
findings are not merged accidentally.

Fallback units remain review workload. They are not automatically false
positives and are not treated as safe. Under the priority policy planned for the
next stage, an unresolved fallback is eligible for tier `U`.

## 7. Column and encoding policy

SARIF/CodeQL columns are interpreted using SARIF's UTF-16-oriented coordinate
semantics. Python `ast` column offsets are UTF-8 byte offsets.

`reconcile-v0` does **not** attempt an automatic cross-encoding column
conversion on source lines containing non-ASCII characters.

Before Rules 1–3 use columns, inspect every source line touched by the compared
finding region and sink span. If any relevant line contains a non-ASCII
character:

```text
mapping_status = column_encoding_requires_review
```

and automatic span matching stops for that finding. The finding is retained
through its fallback identity.

This deliberately follows the conservative behavior already used by
`experiments/build_review.py`.

Line-only evidence may be retained for review, but it must not be promoted to an
automatic mapped unit in v0 merely because the line numbers coincide.

## 8. Determinism and ambiguity

The same normalized findings, sink records, and source contents must always
produce the same units regardless of:

- scanner execution order;
- database insertion order;
- file-system enumeration order;
- Semgrep/CodeQL ordering;
- Python dictionary ordering beyond explicitly canonical serialization.

A finding may map automatically only when the frozen rule establishes a unique
sink and applicable role. Same-file proximity, matching CWE, matching tool
severity, advisory location, or a nearby changed patch line is insufficient.

Multiple raw findings may map to one canonical unit. The reconciler preserves
the contributing raw finding IDs and tool provenance without adding those values
to the unit identity.

## 9. Required output status vocabulary

The v0 reconciler uses at least:

- `mapped`
- `unmapped`
- `role_unresolved`
- `column_encoding_requires_review`

For mapped records it also records one mapping method:

- `explicit_link`
- `containment`
- `exact_span`

No status in this document is a technical vulnerability verdict or scope
verdict.

## 10. Tests required by this freeze

Implementation must add CI-runnable tests covering at minimum:

1. canonical unit ID determinism;
2. CodeQL explicit related-location mapping;
3. strict containment;
4. nested sink selection of the innermost call;
5. exact span mapping;
6. ambiguous incomparable sinks -> fallback;
7. unmapped finding -> fallback;
8. unresolved role preservation;
9. non-ASCII relevant line -> `column_encoding_requires_review`;
10. Python AST discovery for direct imports and aliases;
11. JavaScript reconciliation using recorded sink-locator output;
12. architecture enforcement that `app.triage` imports only the standard
    library and `app.triage.*`.

The real Semgrep JavaScript sink locator is integration-tested in the experiment
Docker workflow; it is not required for pure-unit tests of the reconciler.

## 11. Non-goals for v0

Reconciliation v0 does not:

- infer vulnerability truth;
- infer research scope;
- suppress findings;
- assign P1/P2/U/P3/P4 priority;
- inspect vulnerability patches;
- use held-out outcomes to tune matching;
- merge locations because they are merely nearby;
- execute Semgrep/CodeQL from `app.triage`;
- parse JavaScript with an unpinned third-party Python parser.

Rule-claim annotation and priority assignment may consume the canonical units in
later stages, but they must not retroactively alter this frozen reconciliation
identity or matching order without a new version.
