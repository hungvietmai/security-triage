# Candidate sanitizer review — node-notifier 10.0.1

Status: development hypothesis; unblinded assistant review; no approved truth label.
Technical verdict and threat-model verdict remain unresolved. No policy is applied.

## Exact warning and scope

CodeQL `js/shell-command-constructed-from-input`, raw ID `codeql:0:0`, reports
`lib/utils.js:59` and supplies five code flows through `notifiers/notifysend.js`.
Semgrep supplies two conditional warnings at the same call, naming `notifier` and
`options` as sources. The reported API claim is narrower than a proven exploit.
All three raw results are preserved; sharing a call does not equate their claims.

## Independently inspectable source conditions

- `notifiers/notifysend.js:11`: notifier is the constant `notify-send`.
- `:49-52`: this notification path is restricted to Linux/BSD.
- `:29-30`: notification options are cloned through JSON serialization.
- `:82-96`: option keys use a finite allowlist; title/message are initial arguments.
  This caller does not supply `noEscape` or a custom wrapper.
- `lib/utils.js:287-299`: `noEscape` defaults false and wrapper defaults to a double
  quote for this caller. The same helper supports other configurations elsewhere.
- `:301-312`: arrays recurse; string values pass through `escapeQuotes` and newline
  processing before quote wrapping. `:19-24` escapes double quote, dollar, backtick
  and backslash for strings; non-strings are returned unchanged.
- `:315-329`: initial arguments and allowlisted option values use that function;
  option names are constructed separately from the allowlist.
- `:51-59`: notifier is escaped separately and combined with constructed arguments
  into `cp.exec` shell text. `utils.command` is exported from a deep-importable module.

## What the reported paths require us to check

Several trace paths skip the escape branch in `escapeFn`. Another follows the
non-string branch at `escapeQuotes:23`, while string values require the other branch.
Those paths motivate a type- and call-context-sensitive feasibility check. They
are not proof that the analyzer is wrong: a complete argument must cover coercion,
arrays, all relevant callers and platform behavior, not just an example string.

A plausible **restricted** negative hypothesis is: for the inspected NotifySend
caller, JSON-serializable notification data cannot break out of the intended POSIX
shell argument quoting. That is not yet a site-wide claim. Establish separately:

1. Type propagation from JSON cloning through each reported path, including arrays,
   numbers, booleans, null and object-to-string conversion or exceptions.
2. Effective `noEscape=false`, default wrapper and allowed key set at this caller.
3. Quoting composition under the relevant shell, including backslashes, quote
   combinations, substitutions and newline handling; string replacement alone
   must not be treated as a generic sanitizer for all shells.
4. Whether the label unit includes arbitrary calls to exported `utils.command`.
   A proof for NotifySend cannot eliminate all warnings at that helper's shared sink.
5. Separate shell-command injection from interpretation of options by `notify-send`.
   Argument semantics and shell escaping are different questions.

No package code, native notifier, exploit, or shell payload was executed in this
batch. A future isolated argument-construction harness can collect additional
checks, but finite test cases do not prove universal safety. Human review is still
needed before approving a label or constructing an exclusion rule. Do not change
the evaluation unit after observing this case merely to obtain an FP.

## Relation to the proposed contribution

This case tests context-sensitive sanitizer reasoning, not constant-command R1:
the final command is dynamic. It can guide a future development hypothesis, but
implementing a general shell sanitizer verifier now would materially increase
scope. First review the narrow caller/path evidence and keep the current policy
conservative. If the current location-level unit stays unresolved, retain it and
report the boundary rather than force a negative label.
