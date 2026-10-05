# Grouping and deduplication rules

Status: **pre-scan frozen**  
Date: 2026-10-05  
Applies with: Amendment 02 §6.3–6.5 and Amendment 03 §5.

This document defines the independent vulnerability-group unit before any new
Semgrep/CodeQL pair scan.

## 1. Purpose

The pair inventory contains source-version records, not necessarily independent
vulnerabilities. Repeated commits, repeated affected versions, package aliases,
repository renames and forks must not inflate the development or held-out sample.

Grouping is performed **before** development/held-out/reserve assignment and
must not use scanner outcomes.

## 2. Dataset-specific grouping rules

### 2.1. SecBench.js

The grouping key is the npm package name:

```text
group_id = secbench:<npm-package-name>
```

Examples:

- `curling` -> `secbench:curling`
- `open` -> `secbench:open`
- `@thi.ng/egf` -> `secbench:@thi.ng/egf`

All SecBench.js rows for the same npm package must remain in the same group,
even if they represent different affected versions or advisory records.

The current inventory contains 47 SecBench.js rows and 47 package groups.
Twelve rows/groups are already excluded by source/provenance review; 35 remain
available for later scope/split processing.

### 2.2. PyVul

The grouping key is the canonical GitHub repository identity, compared
case-insensitively:

```text
group_id = pyvul:<lowercase-owner/repository>
```

All PyVul fixing commits from one repository remain in one group.

The current inventory contains 36 PyVul rows and 27 repository groups.

Repositories with more than one PyVul fixing commit are:

| Repository | Rows in inventory |
|---|---:|
| `PaddlePaddle/Paddle` | 3 |
| `mlflow/mlflow` | 3 |
| `WeblateOrg/weblate` | 2 |
| `ansible/ansible` | 5 |

All other PyVul repositories currently contribute one row.

## 3. Cross-dataset duplicate check

A same-looking package/repository name is **not** sufficient evidence for
deduplication.

For cross-dataset checking, use the strongest available repository identity:

1. GHSA `source_code_location` retained in `reference_provenance`;
2. a valid historical fixing-repository reference where GHSA repository
   provenance is unavailable;
3. the PyVul GitHub repository field.

Repository strings are normalized case-insensitively. A GitHub redirect/rename
is treated as the same repository identity when GitHub resolves the historical
name to the same canonical repository.

If a future SecBench.js and PyVul row resolve to the same canonical repository,
they are not automatically merged solely because of repository equality. The
vulnerability/advisory identity and affected code family must also be checked.
Confirmed duplicate records must share one cross-dataset group before split
assignment.

### 3.1. Current cross-dataset result

No current SecBench.js source repository resolves to the same canonical
repository as a PyVul repository.

One name-similar pair was checked explicitly:

- SecBench.js npm package `libnmap` -> `jas-/node-libnmap`
- PyVul repository -> `savon-noir/python-libnmap`

These are different repositories and different language ecosystems, so they are
**not grouped together**.

No cross-dataset duplicate group is created in the current inventory.

## 4. Fork and renamed-repository handling

Repository identity checks use the GitHub repository record where the historical
repository is still resolvable.

### 4.1. Fork rule

If a repository is a fork:

1. record the GitHub parent repository;
2. check whether another candidate belongs to the same upstream repository or
   the same vulnerability family;
3. merge only when the records represent the same underlying vulnerability
   family or duplicated benchmark evidence;
4. otherwise retain separate groups and document the relationship.

Current check:

- SecBench.js source `roest01/node-pdf-image` is a fork of
  `mooz/node-pdf-image`.
- No PyVul candidate maps to either repository.
- Therefore no group merge is required.

The checked PyVul repositories did not report `fork=true`.

### 4.2. Rename/redirect rule

If GitHub resolves an old owner/repository name to a different canonical
`full_name`, the canonical repository name is used for duplicate checking while
the original source string is retained as provenance.

If a historical repository no longer resolves, do not infer a rename from name
similarity alone. Keep the recorded provenance and mark repository identity
unresolved if that identity becomes material to deduplication.

Historical SecBench.js references that no longer resolve do not currently create
a cross-dataset collision and therefore do not change a group assignment.

## 5. Prior exposure

Any group whose source, labels or scanner output has already influenced the
project is development data.

The following current inventory groups are explicitly marked
`split=development`:

| Group | Reason |
|---|---|
| `secbench:curling` | Existing SecBench.js curling case was scanned and used in prior method development |
| `secbench:open` | The npm package `open` was already included in the earlier JavaScript development batch |

The exposure rule applies at **group level**, not version level. A different
version of the same package/repository cannot later be moved into held-out data.

Other previously exposed datasets/cases that are not represented in this pair
inventory remain development evidence under Amendment 02 but do not require a
row-level split change here.

## 6. Group-level split constraint

Development/held-out/reserve assignment must operate on `group_id`, not
`pair_id`.

Therefore:

- every non-excluded row in one group receives the same split;
- an excluded row remains excluded even if another row from the same logical
  family is usable;
- a group containing any previously exposed usable row is development;
- no row from that group may be held out;
- replacement for acquisition failure must follow the precommitted reserve order
  at group level.

Current usable grouping before scope review and final split:

- SecBench.js: 35 usable package groups;
- PyVul: 27 usable repository groups;
- total usable groups before cross-CWE scope filtering: **62**;
- already exposed development groups in this inventory: **2**.

## 7. Freeze rule

Changes to these grouping rules after scanner outcomes are observed require a
new dated amendment or methodological note that identifies the contaminated
groups. Held-out outcomes must never be used to redefine group boundaries.
