# JavaScript matching and the constant-command filter: v0.2 against v0.3

Development experiment of 2026-11-15 for profile `command-injection-v0.3`
([specification](../../../profiles/command-injection-v0.3/PRIORITY_V0_3.md)). It answers two
questions on sources that earlier runs had already scanned with v0.2:

1. *Matching:* how many alerts that v0.2 could not merge into a located call (queue U) does
   v0.3 merge, and does it merge any alert into the wrong call;
2. *Filtering:* what the narrow JavaScript filter rule G4 (constant shell command) moves out of
   the main review list, and whether each such call really has a constant command.

**None of this is an independent test.** Every source was scanned before, and ten of them were
read to find the defects that v0.3 fixes (`used_to_fix` in `sources.json`). The other 74 were
scanned with v0.2 but their code was not read; results are reported for both groups apart.
The only labels here are mechanical ones for a single class (the command is a constant), so
this folder measures that class and no other kind of false positive.

## Files

| Path | Content |
|---|---|
| `collect.py` | `sources` lists the npm sources with a saved v0.2 export; `scan` rescans each once with v0.3 |
| `sources.json` | The 84 sources, where their v0.2 export is, and which were read to design the fix |
| `inputs/`, `collection.log` | v0.3 exports, one folder per source, and what each scan returned |
| `locate_in_worker.py`, `v1-sinks.json` | Call spans the v1 locator reports for each package, produced inside the worker with the pinned Semgrep; used only by the wrong-merge check |
| `compare.py` | The before/after comparison |
| `constant_reference.cjs`, `constant_reference.py` | Reference labels for the class of false positive G4 is about, built with the `espree` parser and no Semgrep: is the command string of each `exec`/`execSync` candidate a constant. Scores G4 against them |
| `results/constant-reference.json` | Their output: 120 candidates, 1 constant, G4 filtered that one and none of the 116 non-constant ones |
| `results/compare.json` | Output of `compare.py` |
| `READING.md` | The diagnosis of the four known matching failures, the reading of filtered calls, and what remains unmatched |

## What was used to fix and what to evaluate

| Data | Role |
|---|---|
| `adb-driver`, `umount` (alerts under `build/`), `kill-process-by-name`, `node-unrar` (two-step alias), `ps-visitor` (promisified alias), `enpeem` | Read to diagnose the matching failures of the second independent check |
| `arpping` | Read to check the one saved alert on a constant command |
| `buns`, `ts-process-promises`, `curling` | Read earlier for the line-ending defect and the first development case |
| The other 74 npm sources | Rescanned and compared without reading their code |
| `experiments/locators/fixtures/sink-locator-v1-cases.js` (18 cases), `rules/semgrep/command-injection-evidence-js-v0.1/tests/cases.js` (20 cases), `backend/tests/triage/test_javascript_matching.py` | Synthetic cases with stated expectations |

## Rebuild

```bash
python experiments/evaluation/js-matching-v0.3/compare.py \
  --json experiments/evaluation/js-matching-v0.3/results/compare.json
```
