# Labels for the JavaScript candidates of v0.3 (CWE-78)

Every JavaScript or TypeScript candidate that profile `command-injection-v0.3` reports on the
84 npm sources of [../js-matching-v0.3/](../js-matching-v0.3/README.md) now has a label:
`vulnerable`, `safe` or `undetermined`. The criteria were fixed first
([PROTOCOL.md](PROTOCOL.md), hashes in [PREREGISTRATION.json](PREREGISTRATION.json)); nothing
was rescanned.

## Who assigned the labels

- **An AI coding assistant assigned them by reading the package source**, at the owner's
  request (2026-11-15). The same assistant wrote the locator and filter rule G4 that are being
  measured, so the labels are not independent of the pipeline.
- **No person has reviewed them.** `reviewed_by` in [labels.json](labels.json) is `null`.
  Until it is filled, every use of these numbers must say "labels assigned by an AI assistant,
  not reviewed by a person".
- The 84 sources are development data of v0.3.

### How to review

```bash
python experiments/evaluation/js-labels-v0.3/label_sheet.py review \
  artifacts/js-labels-v0.3/REVIEW_SHEET.md --cache artifacts/js-labels-v0.3/cache
```

The sheet (ignored by git) shows, for each of the 78 items, the code around the line, the
label, its class and the reason, with a box to agree or change. After reading it, the reviewer
edits the changed labels in `labels.json`, sets `reviewed_by` to their role and the date, lists
the changed ids in `review_note`, and reruns `score_labels.py`.

## Result (labels not reviewed)

140 units: 62 known vulnerable sites (CVE labels) and 78 assistant labels (47 vulnerable,
14 safe, 17 undetermined). Seven more known sites have no candidate.

| Configuration | TP | FP | Undetermined | FN | Precision | Recall ≤ | F1 ≤ |
|---|---:|---:|---:|---:|---:|---:|---:|
| Semgrep alone | 50 | 5 | 10 | 66 | 0.91 | 0.43 | 0.58 |
| CodeQL alone | 91 | 2 | 2 | 25 | 0.98 | 0.78 | 0.87 |
| ESLint alone | 78 | 11 | 9 | 38 | 0.88 | 0.67 | 0.76 |
| Semgrep ∪ CodeQL | 100 | 5 | 12 | 16 | 0.95 | 0.86 | 0.91 |
| All sources | 109 | 14 | 17 | 7 | 0.89 | 0.94 | 0.91 |
| All sources, after filtering | 109 | 13 | 17 | 7 | 0.89 | 0.94 | 0.92 |
| First tiers (P1+P2), after filtering | 94 | 5 | 11 | 22 | 0.95 | 0.81 | 0.87 |

- **Filter step:** 1 safe unit filtered (rule G4, `arpping` `index.js:60`), 0 vulnerable,
  0 undetermined.
- **Safe units left in the review list: 13.** By class: 5 alerts on a `require` line
  (`not_a_command_sink`, all ESLint, all in queue U), 4 `validated_or_escaped`,
  3 `internal_values_only`, 1 `test_or_example_code`. By priority: P1 2, P2 3, U 5, P3 3.
- On the 74 sources whose code was not read while matching was fixed: 125 units, precision of
  all sources 0.88 before and after filtering (the one filtered unit is in the other ten).

Full output: [results/score.json](results/score.json).

## What this supports and what it does not

- With these labels the review list for JavaScript is mostly true positives (109 of 123
  decided units), so the room for removing false positives is small: 14 units.
- The filter step removes 1 of those 14 and no true positive. **It does not reduce the other
  13**; that is the measured answer for false positives outside the constant-command class.
- The 13 fall into classes the pipeline has no evidence for: alerts that point at a `require`
  line, values validated or escaped before use, commands built from values the package itself
  sets (including constants passed through a local wrapper), and test code.
- Recall and F1 are upper bounds: the denominator has only vulnerable locations that a tool or
  a CVE points at.
- A unit is an entry of the review list. Unmatched alerts of one file form one unit, and an
  unmatched alert about a known site is a unit apart from that site (`local-devices`), so units
  are not a count of distinct vulnerabilities.
- 17 units are `undetermined`, most of them packages whose purpose is to run the caller's
  command (`shelljs`, `grunt-shell`, `gulp-shell`, `release-it`, ...). They count neither way.

## Deviation from the registered files

`score_labels.py` failed on its first run: sorting units raised `TypeError` for unmatched
alerts, which have no line. One sort key was changed after the labels were written (registered
SHA-256 `de5981ac…`, current `6aca2dc9…`). The counting code is unchanged, and no label was
changed after the first score was seen.

## Files

| Path | Content |
|---|---|
| `PROTOCOL.md`, `PREREGISTRATION.json` | Criteria and scoring rules fixed before the sheet was built, with hashes |
| `label_sheet.py` | Lists the items; builds the blind labeling sheet and the review sheet from npm |
| `labels.json` | The 78 labels with class and reason, who assigned them and the empty review record |
| `score_labels.py`, `results/score.json` | Scoring against the saved v0.3 exports and its output |

## Rebuild (no stack, no network)

```bash
python experiments/evaluation/js-labels-v0.3/score_labels.py \
  --json experiments/evaluation/js-labels-v0.3/results/score.json
```
