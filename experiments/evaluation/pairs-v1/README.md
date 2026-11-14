# Evaluation of the product pipeline on pairs-v1

Governed by [Amendment 06](../../amendments/AMENDMENT_06_PRODUCT_PIPELINE_ON_PAIRS_V1.md) and
[Amendment 07](../../amendments/AMENDMENT_07_HELD_OUT_POSTPONED.md), both adopted by the project
owner on 2026-11-15: the development split was scanned as a rehearsal with v0.2; the held-out
split stays closed for the next pipeline version. Only vulnerable versions are scanned; the
result is coverage of known vulnerable locations, never precision.

## Status

| Step | State |
|---|---|
| Amendment, scoring kit, labels of both splits, frozen configuration committed | Done before any scan |
| Development split (34 pairs, 26 known locations) | **Scanned on 2026-11-15 with v0.2**: all 34 pairs from the locked bytes, 30 completed, 4 partial. In completed scans the union of all sources reports 21 of 22 known locations (CodeQL alone 18, Semgrep alone 11); 25 of 26 counting partial scans; none filtered. `development/result.json` |
| Held-out split (16 pairs, 9 known locations) | **Not scanned.** [Amendment 07](../../amendments/AMENDMENT_07_HELD_OUT_POSTPONED.md) keeps its single use for the next pipeline version; a new amendment and a new freeze are needed before it is opened |

## Files

| Path | Content |
|---|---|
| `pair_labels.py` | Builds a label file for one split from the locked manifests and known locations; `--verify` tells whether an exported report was produced from the locked archive bytes |
| `score_pairs.py` | `collect` scans every pair of a run once; `score` keeps the pairs scanned from the locked bytes and scores them with `../independent-secbench/configurations.py` |
| `freeze.py` | Records the SHA-256 of every file that decides detection, merging, ranking, filtering and scoring; `gate` re-checks them before the held-out run |
| `FROZEN_CONFIGURATION.json` | The frozen hashes, written before the first development scan |
| `HELD_OUT_GATE.json` | Written by `freeze.py gate` immediately before the first held-out scan |
| `<split>/labels.json` | Vulnerable source and known location of each pair |
| `<split>/inputs/`, `<split>/collection.log` | Exported reports, one folder per pair, and what each scan returned |
| `<split>/result.json` | Output of `score_pairs.py score` |

## Sources

The locked archive cache `artifacts/pair-sources/` is not on the machine used here. Amendment 06
section 4 replaces it with a check: the application acquires each source from the coordinate in
the pair manifest, and a scan is scored only when the SHA-256 the application records equals the
hash in `pairs/sources.lock.json`. A pair with different bytes is listed and left out.

## Run

```bash
python experiments/evaluation/pairs-v1/pair_labels.py development \
  --json experiments/evaluation/pairs-v1/development/labels.json
python experiments/evaluation/pairs-v1/pair_labels.py held_out \
  --json experiments/evaluation/pairs-v1/held_out/labels.json
python experiments/evaluation/pairs-v1/freeze.py write        # then commit

python experiments/evaluation/pairs-v1/score_pairs.py collect experiments/evaluation/pairs-v1/development
python experiments/evaluation/pairs-v1/score_pairs.py score experiments/evaluation/pairs-v1/development \
  --json experiments/evaluation/pairs-v1/development/result.json

python experiments/evaluation/pairs-v1/freeze.py gate         # then commit; stops if a frozen file changed
python experiments/evaluation/pairs-v1/score_pairs.py collect experiments/evaluation/pairs-v1/held_out
python experiments/evaluation/pairs-v1/score_pairs.py score experiments/evaluation/pairs-v1/held_out \
  --json experiments/evaluation/pairs-v1/held_out/result.json
```

Each pair is scanned once. A pair that already has a folder under `inputs/` is skipped, and a
failed or partial scan stays in the result.

## What the result can and cannot show

| Split | Pairs acquired | With a resolved known location | Language of the resolved ones |
|---|---:|---:|---|
| development | 34 | 26 | 21 JavaScript, 5 Python |
| held_out | 16 | 9 | 8 JavaScript, 1 Python |

- It gives coverage of known vulnerable locations per configuration, lost true positives and
  the priority of each known location, on real CVEs.
- It gives **no precision**: the fixed version is not a negative label (pairs/README.md), and
  candidates outside the known location are unlabeled.
- The held-out split has one resolved Python location, so it says almost nothing about the
  filter step, which only has evidence packs for Python.
