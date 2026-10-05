# Pair inventory

This directory contains the pre-scan candidate inventory required by Amendments 02–03.

- Pair schema: `../schemas/pair-manifest.schema.json`
- Inventory: `pair-inventory.csv`
- SecBench.js source snapshot: `5d362353550a8baa42bba34edd26e5fb86d41b60`
- PyVul source snapshot: `1172bfd1579b4ad2a524549412170d08ca618fb3`
- Candidate rows: **83**
  - SecBench.js: **47**
  - PyVul: **36**
- Source-materialization exclusions at migration time: **8**
  - SecBench.js without usable `fixedVersion`: **7**
  - PyVul fixing commit without a parent: **1**
- No scanner output was used to build or filter this inventory.

## Source acquisition policy

### SecBench.js

Use npm tarballs for both snapshots:

- vulnerable snapshot = `vulnerable_version`
- fixed snapshot = `fixed_version`
- `fixCommit` is retained only as reference provenance

A SecBench.js record whose `fixedVersion` is unavailable remains in the
inventory with `split=excluded` and an explicit `exclusion_reason`. The
project does not silently switch those records to Git checkout.

### PyVul

Use pinned GitHub tarballs:

- fixed snapshot = the PyVul fixing commit
- vulnerable snapshot = the first parent of the fixing commit

A fixing commit without a parent remains in the inventory as excluded because
the adopted parent-of-fix rule cannot construct its vulnerable snapshot.

## Field migration

The inventory uses the Amendment 02 §6.1 names plus:

- `group_id`
- `exclusion_reason`
- per-version source fields under the flattened prefixes
  `vulnerable_source.*` and `fixed_source.*`

`dataset_reported_category` is:

- `command-injection` for SecBench.js
- the original PyVul CWE for PyVul

SecBench.js does not assign CWE-77/78/88 at dataset level, so its
`adjudicated_cwe` remains `cwe_unresolved` until the committed GHSA/NVD
provenance step is completed.

Array-like fields such as `reference_provenance` and `cwe_provenance` are
pipe-separated in the CSV and must be decoded before validating a JSON pair
manifest against the schema.

`group_id` is provisional until the grouping/deduplication procedure is frozen.
`split=unassigned` is intentional; development/held-out/reserve assignment has
not yet been performed.

The migration preserves source metadata as published and does not silently repair
suspicious version or fix-commit metadata. Those checks belong to the subsequent
provenance, scope and deduplication review.
