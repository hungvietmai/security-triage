# Amendment 05 — Reassign the JavaScript reserve to development

- Date: 2026-10-08; status: **adopted for development; supervisor agreement pending**.
- Base protocol: v1.0.0, commit `80db12b6f7b275501f9c0f260c90cd05e818491e`.
- Previous amendment: [Amendment 04](AMENDMENT_04_SCOPE_REVIEW.md).
- Frozen split before this amendment: tag `split-v0.1`, commit
  `67f77a381ba2be64b9686f046715223bb508c46c`.
- Pair preparation before this amendment: tag `pairs-v0`, commit
  `3b3256e` (manifests and source locks); repository state immediately before this
  amendment: `b35413d4bd3bc90f1d3c0e8bbac6c2b2225f4dff`.
- **No Semgrep or CodeQL run has been performed on any pair in this amendment or on
  any held-out pair.** The reassigned pairs were downloaded and hash-locked
  (`pairs-v0`) only; their sources were not scanned, built or executed. Scanner runs
  so far concern only the development case `curling@0.2.0` (recorded prior exposure),
  synthetic R1 fixtures, OWASP BenchmarkPython and the development npm batches.

## 1. Reason

Split-v0.1 holds eleven in-scope JavaScript groups in `reserve` because their CWE
could not be adjudicated (`contains cwe_unresolved`). They are not held-out data and,
under Amendment 02, could serve only as replacements for acquisition or build
failures. Python has no reserve; the one Python acquisition failure
(`pyvul:ray-project/ray`, both archives above the 50 MiB bound) therefore has no
replacement either way.

The development set is small for revising the priority policy before the held-out
run. Using these eleven groups as development data adds independent JavaScript
groups for that work. The decision is taken now, before any of them or any held-out
pair has been scanned, so it cannot depend on scanner results.

## 2. Change

Split-v0.2 (`experiments/inventory/split_v0.2.json`) is derived mechanically from
split-v0.1 by `experiments/make_split_v0_2.py`:

- every group whose split-v0.1 assignment is `reserve` becomes `development` and
  records `previous_assignment: "reserve"`;
- held-out and excluded groups, the SHA-256 order and every other field are
  unchanged; nothing is redrawn, and no replacement is performed.

Reassigned groups and pairs:

| Group | Pair |
| --- | --- |
| `secbench:arpping` | `secbench-arpping-2.0.0` |
| `secbench:blamer` | `secbench-blamer-0.1.13` |
| `secbench:clamscan` | `secbench-clamscan-1.2.0` |
| `secbench:extra-asciinema` | `secbench-extra-asciinema-1.0.0` |
| `secbench:git-parse` | `secbench-git-parse-1.0.4` |
| `secbench:growl` | `secbench-growl-1.9.0` |
| `secbench:gry` | `secbench-gry-5.0.8` |
| `secbench:kill-port-process` | `secbench-kill-port-process-0.0.1` |
| `secbench:pdfinfojs` | `secbench-pdfinfojs-0.3.6` |
| `secbench:portprocesses` | `secbench-portprocesses-1.0.4` |
| `secbench:ps` | `secbench-ps-0.0.2` |

Resulting usable manifests: development 35 pairs / 34 groups (JavaScript 25 groups,
Python 9), held-out 16 pairs / 15 groups (unchanged), reserve none.

## 3. Consequences

- **Held-out is unchanged** in membership and order. The pooled held-out minimum
  from Amendment 02 still applies.
- **No reserve remains.** A held-out acquisition or build failure can no longer be
  replaced and is reported as a failure; the pooled held-out total decides whether
  results are reported as broad evidence or as a pilot, as before.
- **CWE remains unresolved** for these groups. They count as development data only;
  any CWE-stratified development summary reports them as `cwe_unresolved`, never
  as CWE-77 or CWE-78.

## 4. Source locks

Only the manifests' `split` field changes. Each affected lock entry is rebound with
`lock_pair_sources.py --rebind-split experiments/inventory/split_v0.2.json`, which
accepts a manifest only if restoring its previous assignment reproduces the locked
manifest hash exactly. The previous hash, field, values, split and this amendment
are recorded under `rebinds`. Archive bytes and hashes are untouched.

## 5. Freeze

The commit adopting this amendment carries the tags `amendment-05` and
`split-v0.2`, before any scan of a reassigned or held-out pair.
