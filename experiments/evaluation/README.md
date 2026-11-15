# Before/after evaluation of the scan pipeline

This directory evaluates the product pipeline as a user sees it: **broad detection →
merging duplicate alerts → evidence-based filtering → before/after report**. Every table is
computed from files the application exports, so it can be rebuilt without Docker, a scanner
or the network.

Results and what they do and do not show: [docs/thesis/chapter-3-results.md](../../docs/thesis/chapter-3-results.md).

## Files

| Path | Content |
|---|---|
| `collect_report.py` | Requests one scan through the public API of a running stack and saves the exported `report.json`, `report.sarif` and a `manifest.json` with their SHA-256 |
| `collect_development.sh` | The exact list of development sources collected for this evaluation |
| `inputs/<source>/` | Saved exports, one folder per scan |
| `before_after.py` | Builds the comparison tables from one saved report and, optionally, a label file |
| `summarize.py` | One table over several saved reports (stage counts and each tool's contribution) |
| `results/` | Committed outputs of `before_after.py` and `summarize.py` |
| `tool-trials/` | The tool-selection trials for the filtering step: trial Semgrep rules, the scripts that ran them and Bandit on a stored snapshot inside the worker, and their output |
| `independent/` | First check on sources this project had never scanned (three deliberately vulnerable applications): protocol, labels and scoring script hashed before the scans (`PREREGISTRATION.json`), the saved exports and the result |
| `independent-secbench/` | Second check: the 52 npm packages with a published command-injection CVE in SecBench.js that the frozen inventory never contained. Labels are built mechanically from the dataset's metadata; `configurations.py` compares Semgrep alone, CodeQL alone, ESLint alone, their unions and the filtered list on the published sites. `DEVIATIONS.md` records the one change made after registration; `posthoc_missed.py` and `posthoc-after-fix/` are labeled post-hoc |
| `independent-python/` | Third check: six documented sites in three deliberately vulnerable Python applications, the language the filter step has evidence packs for |
| `independent-labeled/` | Fourth check, with vulnerable **and** safe labels: 210 lines of the rule tests of semgrep-rules, labeled by the rule authors' `ruleid:`/`ok:` comments. `labeled_sites.py` gives TP/FP/FN/TN, precision, recall and F1 per configuration. The registered scan failed on a defect of the application; `DEVIATIONS.md` separates that registered result from the rescan after the fix |
| `independent-filter/` | Fifth check, on the filter step alone: 20 real Python command-line tools picked by one fixed GitHub search, no labels. `filtered_candidates.py` counts what the filter moved out of the main list in completed scans; `verify_filtered.py` checks every filtered call against the source with a rule fixed before the scans. `READING.md` holds the registered result and the later reading of two calls |
| `pairs-v1/` | The frozen CVE pairs under Amendments 06 to 08: label builder, run and freeze scripts, the development-split run with v0.2, the rehearsal of v0.3 and the **held-out run with v0.3** (16 pairs scanned once from the locked bytes after the configuration was frozen and committed) |
| `js-matching-v0.3/` | Development experiment for profile v0.3: 84 npm sources rescanned, compared with their saved v0.2 exports (unmatched candidates, newly merged alerts, wrong-merge check, filter rule G4) |
| `js-labels-v0.3/` | Labels for every JavaScript candidate of those 84 sources (62 CVE sites, 78 labels assigned by an AI assistant and **not reviewed by a person**), the criteria fixed beforehand and the scoring of the saved v0.3 exports |
| `PIPELINE_CHANGES.json` | Pipeline code files that changed after the registered scans of `independent*/`, with the reason. Protocols, labels, scoring scripts and exports are never listed there |

`experiments/tests/test_evaluation.py` recomputes every file in `results/` from `inputs/` and
checks each saved export against its manifest.

## Rebuild the tables (no stack needed)

```bash
python experiments/evaluation/before_after.py \
  experiments/evaluation/inputs/owasp-benchmarkpython-v0.2 \
  --labels experiments/labels/owasp-python-cwe78-expectations.json \
  --json experiments/evaluation/results/owasp-benchmarkpython-v0.2.json

python experiments/evaluation/summarize.py experiments/evaluation/inputs \
  --json experiments/evaluation/results/summary.json

python experiments/evaluation/independent/known_sites.py \
  experiments/evaluation/independent/labels.json \
  experiments/evaluation/independent/inputs \
  --json experiments/evaluation/independent/results/known-sites.json

L=experiments/evaluation/independent-labeled
python $L/labeled_sites.py $L/labels.json $L/input/report.json \
  --json $L/results/registered.json
python $L/labeled_sites.py $L/labels.json $L/posthoc-after-fix/report.json \
  --json $L/results/posthoc-after-fix.json

F=experiments/evaluation/independent-filter
python $F/filtered_candidates.py $F/sources.json $F/inputs \
  --json $F/results/filtered-candidates.json
# verify_filtered.py reads the pinned source files from GitHub; its saved output is
# $F/results/verified.json

for wave in independent-secbench independent-python; do
  python experiments/evaluation/independent-secbench/configurations.py \
    experiments/evaluation/$wave/labels.json experiments/evaluation/$wave/inputs \
    --json experiments/evaluation/$wave/results/configurations.json
done
```

## Collect the inputs again (needs the stack)

```bash
docker compose up --build -d --wait --wait-timeout 900
sh experiments/evaluation/collect_development.sh
```

Each scan downloads its source from npm or GitHub and runs the pinned scanners in the worker.
A new collection produces new scan IDs and timings; alert counts, candidates and dispositions
are expected to stay the same for the same snapshot, profile and tool versions.

## Scope and rules

- **`inputs/` is development data only.** Every source there was already scanned by an earlier
  phase (`experiments/cases/`, wave A, wave C). The filter rules and the CWE-78 evidence
  mechanisms were developed with these sources in view, so none of it is an independent test.
- **`independent*/` were scanned once, after their protocols were hashed.** Do not rescan those
  sources or edit the files listed in each `PREREGISTRATION.json`: a test compares them, and
  accepts only the change recorded in `independent-secbench/DEVIATIONS.json`. They hold
  documented vulnerable sites and no safe labels, so they give coverage and lost true
  positives, never precision. Results on 2026-11-14: 3/3 sites reported (first check), 32 of
  43 in completed scans (second; CodeQL alone 27, Semgrep alone 12), 6/6 (third); no
  documented site was filtered.
- **`independent-labeled/` is the only independent data with safe labels.** Its registered
  scan failed (a Python file with a syntax error stopped the sink locator); every number with
  precision or F1 comes from the single rescan after that fix and must be quoted as such:
  all sources P 0.66 / R 0.71 / F1 0.69, Semgrep alone 0.88 / 0.36 / 0.51, CodeQL alone
  1.00 / 0.15 / 0.26. The rescan was partial, so the filter step, by design, filtered nothing.
- **`independent-filter/` has no labels.** It shows the filter acting on unseen code in completed
  scans (19 of 145 candidates, all by the constant-command rule G2; the registered check
  accepted 17 and rejected 2, both of which a later reading found to be constant commands
  wrapped in another call). It says nothing about detection or about lost true positives.
- **`pairs-v1/`: both splits have been scanned once.** The development split with v0.2, the
  held-out split with v0.3 on 2026-11-15 (union of all sources: 9 of 9 known locations, none
  filtered). Do not rescan either; the held-out split is no longer independent data.
- **`js-matching-v0.3/` is development data**: every source was scanned before and ten were
  read to design the change. It measures matching, not false-positive reduction.
- **`js-labels-v0.3/` uses labels assigned by an AI assistant that no person has reviewed.**
  Say so wherever its numbers are used, until `reviewed_by` in its `labels.json` is filled.
- **Counting unit:** the review candidate, one call. A labeled site is reported by a
  configuration when any of its candidates is in it. Candidates outside every labeled site
  are counted as unlabeled and never scored.
- **Labels:** `experiments/labels/owasp-python-cwe78-expectations.json` holds the upstream
  OWASP expectations (13 vulnerable, 7 safe CWE-78 sites). They are the benchmark author's
  labels, checked by one unblinded source review; see
  `experiments/reports/owasp-python-development/REPORT.md`.
- **Filter criteria were fixed in code before these reports were scored**
  (`backend/app/triage/adjudicate.py`, version `adjudicate-v0.2`). They were not tuned on the
  scores printed here; they were, however, designed knowing this benchmark's negative cases.
- A candidate can satisfy several filter rules. `before_after.py` counts it under each, and
  reports separately what filtering would leave if only rules backed by an open-source tool
  (Semgrep, Bandit) applied.
