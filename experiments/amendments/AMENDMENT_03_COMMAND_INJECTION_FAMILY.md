# Amendment 03 — Command-injection family scope

- Date: 2026-10-05; status: **adopted for development; supervisor agreement pending**.
- Base protocol: v1.0.0, commit `80db12b6f7b275501f9c0f260c90cd05e818491e`.
- Previous amendment: [Amendment 02](AMENDMENT_02_APPLICATION_TRIAGE.md).
- Repository state immediately before this amendment:
  `232f7b1fe4b3939d783dfef319ce23b5404217ab`.
- This amendment changes the primary vulnerability-family scope defined by
  Amendment 02. All other methodological controls, split rules, ranking
  baselines, review rules, development budgets and freeze requirements remain
  in force unless explicitly changed below.
- **No new vulnerability-pair scan result had been produced or inspected after
  Amendment 02 and before the commit adopting this amendment.** The scope change
  is therefore made before observing outcomes from the new pair inventory.

## 1. Reason for the scope change

Amendment 02 retained CWE-78 as the primary class and treated CWE-77 and CWE-88
as adjacent strata. Inventory planning indicates that this separation may leave
too few independent CWE-78 groups after deduplication, prior-exposure exclusion,
acquisition constraints and the development/held-out split.

The project therefore adopts a broader but still technically bounded primary
scope: the **command-injection family consisting of CWE-77, CWE-78 and CWE-88**.

This change is intended to increase the number and diversity of independently
known command-injection cases without expanding the study to unrelated taint
families.

The study must still report results separately for CWE-77, CWE-78 and CWE-88 in
addition to any pooled command-injection-family result. Pooling does not erase
per-CWE provenance, counts, failures or limitations.

## 2. Primary scope

The primary deep-validation scope is now:

- CWE-77 — Improper Neutralization of Special Elements used in a Command;
- CWE-78 — Improper Neutralization of Special Elements used in an OS Command;
- CWE-88 — Improper Neutralization of Argument Delimiters in a Command.

The primary languages remain Python and JavaScript.

The threat model remains Linux/POSIX unless a later amendment changes it before
held-out evaluation.

For every included vulnerability group, retain:

- dataset-reported category;
- every CWE reported by authoritative sources;
- adjudicated CWE used for stratification;
- CWE provenance and any conflict;
- language;
- repository/vulnerability-family group;
- scope verdict and reason where manual scope review is required.

Primary tables must report:

1. pooled command-injection-family counts for CWE-77/78/88;
2. separate CWE-77 counts;
3. separate CWE-78 counts;
4. separate CWE-88 counts;
5. unresolved-CWE cases separately.

Small per-CWE cells are reported as exact counts rather than percentage-only
summaries.

## 3. Additional scope condition for CWE-77

CWE-77 is broader than operating-system command injection and may describe
injection into command or interpreter contexts that are not part of this
project's execution threat model.

A CWE-77 case is eligible for the primary study only when the vulnerable
behavior reaches a sink that, under the Linux/POSIX threat model, performs or
initiates **operating-system process or command execution**.

Eligible examples may include, subject to case-specific review:

- direct process or shell execution;
- construction of a command passed to a system shell;
- execution through a process-spawning API where injected command structure or
  arguments can alter the intended operating-system command behavior;
- a wrapper or helper whose relevant security effect is ultimately OS
  process/command execution.

A CWE-77 case is **out of primary scope** when its vulnerable sink is limited to
another interpreter or command language whose security effect does not constitute
OS process/command execution under the frozen Linux/POSIX threat model.

Examples requiring exclusion or explicit separate treatment include injection
whose relevant sink is only:

- a database/query interpreter;
- a template interpreter;
- an application-specific command language;
- another parser/interpreter without an OS process/command-execution effect.

The CWE label alone does not establish eligibility.

For every CWE-77 candidate, record a scope decision with at least:

```text
scope_verdict: in_scope | out_of_scope | unresolved
scope_reason
sink_kind
os_command_execution_basis
review_provenance
```

A case marked `out_of_scope` must be excluded from the primary detection and
ranking denominator while remaining visible in the inventory with its exclusion
reason.

A case marked `unresolved` must not be silently included in the primary
evaluation. Resolve it under the review protocol or report it separately.

Human scope labels remain evaluation metadata and must not be used as runtime
features in Mode A. If an automated scope extractor is later developed, it must
follow Amendment 02's freeze and held-out rules.

## 4. CWE provenance remains mandatory

The CWE provenance and conflict-resolution rules introduced by Amendment 02
remain unchanged.

In particular:

- PyVul dataset annotations are retained with their source records;
- SecBench.js category labels alone do not determine CWE-77/78/88;
- GHSA explicit CWE assignments take precedence when available, followed by NVD,
  then a maintainer/vendor advisory where necessary;
- authoritative disagreement is preserved and reviewed rather than resolved for
  convenience;
- `cwe_unresolved` remains a distinct state.

The expanded primary family must not be used to relabel cases whose CWE remains
unsupported.

## 5. Consequences for data splitting and evaluation

The development/held-out/reserve split required by Amendment 02 is now formed
over eligible independent groups in the pooled CWE-77/78/88 command-injection
family, while stratifying by CWE, language and dataset where inventory size
permits.

Repository/vulnerability-family grouping and prior-exposure exclusions remain
unchanged.

The study should preserve the Amendment 02 target of leaving at least 40% of
otherwise eligible fresh primary-scope groups held out where the inventory
permits.

A minimum of ten successful independent held-out primary-family groups remains
the threshold below which results are reported as pilot/feasibility evidence
rather than broad effectiveness evidence.

RQ1, RQ3 and RQ4 are now interpreted over the eligible CWE-77/78/88 primary
family. Results must additionally be broken down by individual CWE so that any
pooled improvement cannot hide materially different behavior across CWE-77,
CWE-78 and CWE-88.

No separate superiority claim is made for an individual CWE whose sample is too
small to support one.

## 6. No change to the application deliverable

This amendment does not broaden the validated evidence engine to arbitrary
vulnerability classes.

Mode A remains the application-centered scan-and-triage system defined by
Amendment 02. The platform may ingest other configured rule/query families, but
the deep evidence model, root-cause development, priority-policy evaluation and
held-out effectiveness claims are limited to the eligible CWE-77/78/88
command-injection family.

Mode B continues to provide evaluation and regression testing over versioned
vulnerability manifests.

## 7. Freeze and audit boundary

At the time this amendment is adopted:

- no new vulnerability-pair scan result has been produced or inspected since
  Amendment 02;
- no new pair outcome has been used to select CWE-77, CWE-78 or CWE-88 for
  inclusion;
- no held-out outcome has been used to define the CWE-77 OS-command-execution
  scope rule above.

Before scanning new vulnerability pairs, the project must still commit the
remaining Amendment 02 pre-scan artifacts:

1. pair-manifest schema;
2. candidate inventory with CWE and reference provenance;
3. CWE-77 scope decisions or the procedure and fields needed to produce them;
4. grouping/deduplication rules;
5. deterministic development/held-out/reserve split;
6. initial root-cause taxonomy;
7. ranking baseline definitions;
8. priority-policy version.

This amendment must be committed before those new pair scans.

The adoption commit should be marked with the repository tag
`amendment-03`. The tag URL and service-recorded time must be retained in the
research log. A local-only tag or manually written timestamp is not sufficient
evidence of publication ordering.
