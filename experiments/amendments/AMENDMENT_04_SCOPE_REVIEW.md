# Amendment 04 — Pre-scan scope review for the command-injection family

- Date: 2026-10-05; status: **adopted for development; supervisor agreement pending**.
- Base protocol: v1.0.0, commit `80db12b6f7b275501f9c0f260c90cd05e818491e`.
- Previous amendment: [Amendment 03](AMENDMENT_03_COMMAND_INJECTION_FAMILY.md).
- Frozen split before this amendment: tag `split-v0`, commit
  `72972469ea7b8da895ba4a3bdc2309676b04a953`.
- Repository state immediately before this amendment:
  `c78eed57aa8869257ee170b9294711c7f058609d`.
- **No new Semgrep/CodeQL vulnerable-pair scan result had been produced or
  inspected after split-v0 and before adoption of this amendment.** Patch/advisory
  inspection performed to identify scope risk does not constitute a scanner run.

## 1. Reason for the amendment

Amendment 03 expanded the primary family to CWE-77/CWE-78/CWE-88 but stated the
explicit operating-system command-execution sink condition only for CWE-77.

Pre-scan inspection of public vulnerable/fixed evidence showed that dataset CWE
labels can include cases whose repaired behavior concerns language evaluation,
template interpretation, unsafe deserialization, URL handling, or other
interpreter/application behavior rather than Linux/POSIX operating-system
process/command execution.

This can occur even when a public dataset labels a case CWE-78. If such cases
remain in the primary denominator, a command-injection detector can appear to
miss vulnerabilities that are outside the detector's declared threat model.

The scope condition is therefore generalized before any new pair scan.

## 2. Scope condition applies to CWE-77, CWE-78 and CWE-88

A candidate in any of CWE-77, CWE-78 or CWE-88 is eligible for the primary
deep-validation study only when the vulnerable behavior reaches, or directly
controls, a sink that under the frozen Linux/POSIX threat model performs or
initiates **operating-system process or command execution**.

The CWE label alone is not sufficient evidence of scope.

Eligible behavior includes, subject to case-specific review:

- direct shell or operating-system command execution;
- direct process spawning where attacker-controlled command structure,
  executable selection, argument delimiters, options, or arguments can change
  the intended operating-system command behavior;
- a wrapper/helper whose relevant vulnerable effect ultimately reaches OS
  process/command execution;
- argument injection into an operating-system command invocation.

Out-of-scope behavior includes cases whose relevant vulnerable effect is limited
to another interpreter/application mechanism without OS process/command
execution, including for example:

- language-level code evaluation;
- template-language interpretation;
- unsafe object or YAML deserialization;
- database/query interpretation;
- URL validation/navigation without an OS execution sink;
- application-specific parsers or command languages that do not initiate OS
  process/command execution.

A case is not made in-scope merely because OS command execution could occur
indirectly in some hypothetical environment. The reviewed advisory/patch must
support the relevant OS execution relationship for the vulnerability under study.

## 3. Scope evidence and review procedure

Scope decisions are made **without using Semgrep or CodeQL output**.

Use the following evidence, in order of practical relevance:

1. the authoritative advisory record and its package/repository identity;
2. the vulnerable/fixed code change or security fix patch;
3. dataset metadata such as known sink/location where it is independently
   traceable to the reviewed vulnerability;
4. repository context needed to determine whether the changed construct reaches
   an OS process/command execution sink.

Record at least:

```text
scope_verdict: in_scope | out_of_scope | unresolved
scope_reason
sink_kind
os_command_execution_basis
scope_review_provenance
```

The reviewer may use a script to download patches and highlight candidate
security-relevant tokens, but keyword matches are only review aids and must not
determine the verdict automatically.

## 4. Treatment of scope verdicts

- `in_scope`: remains in its frozen split assignment.
- `out_of_scope`: excluded from the primary detection/ranking denominator.
- `unresolved`: does not enter the primary denominator and is retained as
  reserve/unresolved evidence until resolved.

Out-of-scope or unresolved groups are **not replaced** by another group in the
held-out set.

The original split-v0 hash order and assignment of every remaining in-scope group
must remain unchanged. The project must **not rerun the held-out draw** after
scope review.

A derived artifact `split-v0.1` records only these pre-scan scope exclusions
and unresolved reservations while preserving the split-v0 order and membership
for all remaining in-scope groups.

## 5. Reporting consequences

The final report must state:

- how many candidate groups were removed or reserved by scope review;
- counts by language and adjudicated CWE;
- how many held-out groups remain after scope filtering;
- that no replacement was performed;
- that the original split-v0 hash order was preserved.

If a language-specific held-out stratum becomes small, the project must not make
a strong language-specific effectiveness claim merely because the pooled
held-out total remains adequate.

The minimum pooled held-out threshold from Amendment 02 remains unchanged.

## 6. Split-generator correction

The current split generator's use of the mutable `split` column as evidence of
prior exposure can make reruns non-idempotent.

Before scanner execution:

1. prior exposure must be represented separately from generated split state;
2. the generator must reproduce the frozen split from immutable inputs;
3. a check/verification mode must compare generated output without mutating the
   inventory;
4. tests must confirm idempotence and preservation of the frozen split.

This correction must not alter the already published split-v0 assignment.

## 7. Freeze boundary

This amendment is adopted before the full usable inventory is reviewed for
OS-command-execution scope and before any new vulnerable-pair Semgrep/CodeQL scan.

The scope-review artifact, derived split-v0.1, corrected split generator and its
tests must be committed before new pair scanning begins.

This amendment should be published with tag `amendment-04`; the tag URL and
service-recorded publication time must be retained in `experiments/RESEARCH_LOG.md`.
