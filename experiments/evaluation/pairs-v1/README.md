# Evaluation of the product pipeline on pairs-v1

Governed by Amendments [06](../../amendments/AMENDMENT_06_PRODUCT_PIPELINE_ON_PAIRS_V1.md),
[07](../../amendments/AMENDMENT_07_HELD_OUT_POSTPONED.md) and
[08](../../amendments/AMENDMENT_08_HELD_OUT_WITH_V0_3.md), all adopted by the project owner on
2026-11-15. Only vulnerable versions are scanned; the result is coverage of known vulnerable
locations, never precision.

## Status

| Step | State |
|---|---|
| Development split with v0.2 (Amendment 06) | **Done.** 34 pairs from the locked bytes, 30 completed, 4 partial. Union of all sources: 21 of 22 known locations in completed scans (CodeQL alone 18, Semgrep alone 11); 25 of 26 counting partial scans; none filtered. `development/result.json` |
| Rehearsal of v0.3 on the Python development pairs (Amendment 08) | **Done.** 9 pairs, 7 completed, 2 partial, none failed; the 5 known locations as with v0.2. `development-v0.3-python/result.json` |
| Freeze and gate for v0.3 | **Done.** `FROZEN_CONFIGURATION_v0.3.json` committed at `b06553e`; `HELD_OUT_GATE.json` committed at `1158f71`, before the first held-out scan |
| **Held-out split with v0.3** | **Done, once, on 2026-11-15.** 16 pairs from the locked bytes, 12 completed, 4 partial, none failed. Union of all sources: **7 of 7** known locations in completed scans (CodeQL alone 6, Semgrep alone 3, ESLint alone 4); **9 of 9** counting partial scans; none filtered; 6 of 7 in P1 or P2. `held_out/result.json` |

**The held-out split is now exposed.** It cannot serve as an independent test of a later version.
Do not rescan it and do not edit `held_out/labels.json` or the files in
`FROZEN_CONFIGURATION_v0.3.json` as a way to change this result.

## Files

| Path | Content |
|---|---|
| `pair_labels.py` | Builds a label file for one split from the locked manifests and known locations; `--verify` tells whether an exported report was produced from the locked archive bytes |
| `score_pairs.py` | `collect` scans every pair of a run once with the given profile; `score` keeps the pairs scanned from the locked bytes and scores them with `../independent-secbench/configurations.py` |
| `freeze.py` | Records the SHA-256 of every file that decides detection, merging, ranking, filtering and scoring for v0.3; `gate` re-checks them before the held-out run |
| `FROZEN_CONFIGURATION.json` | Frozen hashes of the v0.2 development run (commit `f1e7c0c`) |
| `FROZEN_CONFIGURATION_v0.3.json`, `HELD_OUT_GATE.json` | Frozen hashes of v0.3 and the record of the check made immediately before the first held-out scan |
| `<run>/labels.json` | Vulnerable source and known location of each pair |
| `<run>/inputs/`, `<run>/collection.log` | Exported reports, one folder per pair, and what each scan returned |
| `<run>/result.json` | Output of `score_pairs.py score` |
| `development/filtered-check.json` | The 71 candidates the filter removed in the v0.2 development run, checked against their source: all have a constant command |

Runs: `development/` (v0.2), `development-v0.3-python/` (rehearsal), `held_out/` (v0.3).

## Sources

The locked archive cache `artifacts/pair-sources/` is not on the machine used here. Amendment 06
section 4 replaces it with a check: the application acquires each source from the coordinate in
the pair manifest, and a scan is scored only when the SHA-256 the application records equals the
hash in `pairs/sources.lock.json`. In all three runs every pair had the locked hash.

## Rebuild the results (no stack needed)

```bash
for run in development development-v0.3-python held_out; do
  python experiments/evaluation/pairs-v1/score_pairs.py score \
    experiments/evaluation/pairs-v1/$run --json experiments/evaluation/pairs-v1/$run/result.json
done
python experiments/evaluation/pairs-v1/pair_labels.py held_out \
  --verify experiments/evaluation/pairs-v1/held_out/inputs
```

## What the held-out result shows and does not show

| Split | Pairs acquired | With a resolved known location | Language of the resolved ones |
|---|---:|---:|---|
| development | 34 | 26 | 21 JavaScript, 5 Python |
| held_out | 16 | 9 | 8 JavaScript, 1 Python |

- It shows that on nine known vulnerable locations of real CVEs that the project had never
  scanned, the union of all sources reported every one, one more than CodeQL alone, and that
  filtering removed none.
- It gives **no precision**: the fixed version is not a negative label (pairs/README.md), and
  the 156 candidates outside the known locations are unlabeled.
- It says almost nothing about the filter step: one known location is Python, the filter
  removed no candidate at all in this run, and four scans were partial.
- Nine locations are too few for a rate; the result is reported as counts.
