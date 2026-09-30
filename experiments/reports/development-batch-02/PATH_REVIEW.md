# NotifySend path review and bounded diagnostic

2026-09-30. Development evidence; no approved labels, policy exclusions or metrics.
Source: preserved node-notifier 10.0.1 snapshot, SHA-256
`5e75d1bb41696f3334481ec083204335e519920d292855cb6afb6b0e2d9afe9b`.
The review is unblinded and has not received independent human approval.

## Decision

Retain all three warnings at `lib/utils.js:59` for review. There is stronger evidence
for the specific NotifySend argument-construction path, but that does not establish
safety of arbitrary calls to the exported `utils.command` helper. No R1 exclusion
is justified: the command is dynamic, not a constant expression.

## Four traces, not five

Both preserved attempts contain one CodeQL result with **four** `codeFlows`, each
with one `threadFlow`. Earlier notes incorrectly said five; source evidence was
not modified. Rows below use zero-based indexes in the selected attempt's SARIF.

| Flow | Displayed helper locations | What can be inferred |
| --- | --- | --- |
| 0 | `escapeFn:301`, wrapper `:312`, option value `:326` | Escaping nodes are not shown; this is not a full control-flow trace and does not establish bypass |
| 1 | `escapeFn:307`, `escapeQuotes:19,23`, wrapper `:312`, initial arguments `:315-316` | A non-string return is represented; non-string input alone does not demonstrate command injection |
| 2 | recursive array `:303`, newline processing `:310,332,334`, wrapper `:312` | Array/coercion behavior needs separate analysis; absent nodes cannot establish the branch outcomes |
| 3 | option-value construction `:326`, array update `:324`, wrapper `:312` | Array summaries and merged updates do not describe one concrete, executable sequence by themselves |

`notifyRaw` clones options through JSON. In the inspected caller, the argument
builder receives an explicit allowlist and no `noEscape`, custom wrapper or
`explicitTrue` setting. Under ordinary, unmodified built-in prototypes these
settings imply escaping enabled, double-quote wrapping and ordinary option-value
pairs. This caller constraint must not be generalized to every use of the helper.

For ordinary JSON values: strings enter the escaping branch; finite numbers,
booleans and null stringify without shell operators; arrays recurse. Plain object
conversion and failed coercion require care. Functions, symbols and custom live
conversion methods are outside this JSON-cloned input assumption. Prototype
pollution, changed process environment and executable search-path attacks are not
proved absent by inspecting argument escaping.

## Controlled diagnostic

[`check_notifier_quoting.py`](../../diagnostics/check_notifier_quoting.py) verifies
source hashes and extracts only reviewed function slices: clone/escaping/flag map,
option mapping, array detection, argument construction and `doNotification`.
It replaces `utils.command` with a collector. The whole package, dependencies,
`notify-send` binary and native notifiers are never loaded or executed. The helper
is configured for Linux; OS/installation/callback checks in `notifyRaw` are outside
this diagnostic. Function extraction is a reduction, not an integration test.

The corpus contains 166 string cases (message and icon), six JSON-type cases and
two boundary cases. Strings include quote/backslash combinations, whitespace,
substitution syntax, glob characters, Unicode and option-like text. The script
contains its fixed corpus; it does not execute user-supplied shell snippets.
The shell command uses only `set` and `printf` to capture parsed arguments; two
negative controls use a harmless `printf TRIAGE_PROBE` substitution. Each subprocess
has a timeout, minimal environment and a temporary working directory. This is a
controlled test, not a security sandbox for arbitrary untrusted programs.

| Observation | Result |
| --- | ---: |
| String cases matching expected argument bytes | 166/166 |
| Other JSON-type cases matching expected bytes | 6/6 |
| Empty-array case, expected missing value word | 1/1 |
| Non-callable `toString`, expected TypeError before shell parsing | 1/1 |
| Shell argument checks across dash and Bash POSIX mode | 346/346 |
| Deliberately unescaped substitution controls detected | 2/2 |

The empty-array case changes argument arity: `--icon` is followed immediately by
`--expire-time`. It is not an injection counterexample and not a successful value
round-trip. The TypeError case is likewise not evidence of safe successful
processing. All outcomes and constructed arguments are preserved in
`quoting-diagnostic.json`, including source/corpus/runner hashes and shell binary
hashes. No NUL or unpaired-surrogate cases, other operating systems, all possible
values, or actual notify-send option semantics are covered.

Bash's documented double-quote rules provide the interpretation context:
https://www.gnu.org/software/bash/manual/html_node/Double-Quotes.html . The
observations here come from the executed probes, not from assuming that any
function named escape is a sanitizer. Finite success is not a universal proof.

Reproduce from repository root (Node, Python, `/usr/bin/dash`, `/usr/bin/bash`):

```bash
python experiments/diagnostics/check_notifier_quoting.py \
  --evidence experiments/reports/development-batch-02/npm-node-notifier-10.0.1-evidence.json \
  --output artifacts/notifier-quoting-new.json
```

The output path must not exist. Source hashes guard against silently testing a
changed package. Any change to this diagnostic is development work and must be
reported; it is not a new real-world ground-truth sample.

## Pinned query inspection

The scan uses `javascript-queries 2.4.6` and `javascript-all 2.10.2`. The inspected
`UnsafeShellCommandConstructionQuery.qll` defines sources/sinks and barrier
predicates and uses global taint tracking. Its customizations include known
sanitizers, guards for numbers/booleans, and a chain-of-replacements heuristic.
This is useful context, not proof that any particular abstraction caused this
alert. Query/model changes and an ablation would be required to establish that
causal claim. No query, Semgrep rule or model was changed in this follow-up.

## Next decision

Request a human review of the scoped source argument and the diagnostic limitations.
If accepted, record a caller/path-specific assessment while leaving the shared
location unresolved unless its full contract can be covered. Do not narrow the
evaluation unit after seeing this case merely to obtain an FP. To evaluate an
exclusion policy, a real alert with a defensible label at the existing unit is
still needed. A general sanitizer verifier would be additional scope, not a small
implementation of constant-command R1.
