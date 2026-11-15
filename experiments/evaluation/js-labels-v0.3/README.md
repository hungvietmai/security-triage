# Labels for the JavaScript candidates of v0.3 (CWE-78)

Every JavaScript or TypeScript candidate that profile `command-injection-v0.3` reports on the
84 npm sources of [../js-matching-v0.3/](../js-matching-v0.3/README.md) now has a label:
`vulnerable`, `safe` or `undetermined`. The criteria were fixed first
([PROTOCOL.md](PROTOCOL.md), hashes in [PREREGISTRATION.json](PREREGISTRATION.json)); nothing
was rescanned.

## Who assigned and who reviewed the labels

- **An AI coding assistant assigned all 78 labels by reading the package source**, at the
  owner's request (2026-11-15). The same assistant wrote the locator and filter rule G4 that
  are being measured, so its labels are not independent of the pipeline.
- **The project owner reviewed 31 of them on 2026-11-15**: every label the assistant had
  assigned `safe` (14) or `undetermined` (17), one by one with the code excerpt. The owner
  changed 12 (10 labels, 2 classes); each decision and note is in the `review` field of
  [labels.json](labels.json).
- **The 47 labels the assistant assigned `vulnerable` have not been reviewed by a person**
  (`review` is `null`). Counts of false positives therefore rest on reviewed labels; counts of
  true positives include 47 unreviewed ones, and must be reported with that note.
- The 84 sources are development data of v0.3.

### What the review changed

| Item | Assistant | Owner |
|---|---|---|
| `@thi.ng/egf` `lib/index.umd.js`, `git-parse` `dist/checkout_commit.js`, `dist/git_diff.js` (alerts on the `require` line) | safe, not a command sink | **vulnerable**: the module contains the vulnerable call; an alert on a `require` line is labeled by the command calls of its module |
| `git-parse` `dist/git_log_stream.js`, `dist/git_pull.js` | safe, not a command sink | safe, as `no_shell` and `constant_command` |
| `roar-pidusage` `lib/helpers.js:12` | safe, internal values only | **vulnerable**: `getconf` is exported |
| `launch-editor` `index.js:167`, `:172` | undetermined | **vulnerable** (CVE-2026-112943, CVE-2026-112944) |
| `react-dev-utils` `openBrowser.js:92` | undetermined | **vulnerable** (CVE-2026-14802) |
| `nodemon` `lib/monitor/run.js:430`, `:434` | undetermined | safe: `child.kill(signal)` validates the signal first |
| `monorepo-build` `lib/index.test.js:12` | safe, test code | undetermined: a test file alone does not make it safe |

The CVE identifiers are the reviewer's; the three from 2026 were looked up and exist for those
packages.

### Reviewing the remaining 47

```bash
python experiments/evaluation/js-labels-v0.3/review_pending.py \
  artifacts/js-labels-v0.3/REVIEW_VULNERABLE_47.md --cache artifacts/js-labels-v0.3/cache
```

The file (ignored by git) lists each unreviewed label with its code, reason and a decision line.
After it is read, the `review` field of those labels is filled and `score_labels.py` is rerun.

## Result (31 labels reviewed, 47 vulnerable labels not reviewed)

140 units: 62 known vulnerable sites (CVE labels) and 78 labels (54 vulnerable, 11 safe,
13 undetermined). Seven more known sites have no candidate.

| Configuration | TP | FP | Undetermined | FN | Precision | Recall ≤ | F1 ≤ |
|---|---:|---:|---:|---:|---:|---:|---:|
| Semgrep alone | 52 | 4 | 9 | 71 | 0.93 | 0.42 | 0.58 |
| CodeQL alone | 92 | 2 | 1 | 31 | 0.98 | 0.75 | 0.85 |
| ESLint alone | 83 | 9 | 6 | 40 | 0.90 | 0.67 | 0.77 |
| Semgrep ∪ CodeQL | 103 | 4 | 10 | 20 | 0.96 | 0.84 | 0.90 |
| All sources | 116 | 11 | 13 | 7 | 0.91 | 0.94 | 0.93 |
| All sources, after filtering | 116 | 10 | 13 | 7 | 0.92 | 0.94 | 0.93 |
| First tiers (P1+P2), after filtering | 97 | 4 | 9 | 26 | 0.96 | 0.79 | 0.87 |

- **Filter step:** 1 safe unit filtered (rule G4, `arpping` `index.js:60`), 0 vulnerable,
  0 undetermined. All 11 safe labels were reviewed by the owner.
- **Safe units left in the review list: 10.** By class: 6 `validated_or_escaped`,
  2 `internal_values_only`, 1 `constant_command` (`git-parse` `dist/git_pull.js`: the call was
  not located, so G4 had nothing to act on), 1 `no_shell`. By priority: P1 2, P2 2, U 2, P3 4.
- On the 74 sources whose code was not read while matching was fixed: 125 units, the one
  filtered unit is in the other ten.

Full output: [results/score.json](results/score.json).

## What this supports and what it does not

- The review list for JavaScript is mostly true positives (116 of 127 decided units), so the
  room for removing false positives is small: 11 units.
- The filter step removes 1 of those 11 and no true positive. **It does not reduce the other
  10**; that is the measured answer for false positives outside the constant-command class,
  on labels a person reviewed.
- Most of the 10 need evidence the pipeline does not have: a value validated or escaped before
  use (6), a command built from values the package itself sets (2), a call without a shell (1).
- **Matching gap found by the review:** in `git-parse` the calls `exec(...)` on
  `dist/checkout_commit.js:34` and `dist/git_diff.js:22` are vulnerable and no tool located
  them (Babel interop `_child_process.default.exec` wrapped by a promisify helper). The only
  trace is ESLint's alert on the `require` line, kept in queue U. This is why queue U must
  stay in the review list.
- Recall and F1 are upper bounds: the denominator has only vulnerable locations that a tool or
  a CVE points at.
- A unit is an entry of the review list. Unmatched alerts of one file form one unit, and an
  unmatched alert about a known site is a unit apart from that site (`local-devices`), so units
  are not a count of distinct vulnerabilities.
- 13 units are `undetermined`, most of them packages whose purpose is to run the caller's
  command (`shelljs`, `grunt-shell`, `gulp-shell`, `release-it`, ...). They count neither way.

## Deviations from the registered files

- `score_labels.py` failed on its first run: sorting units raised `TypeError` for unmatched
  alerts, which have no line. One sort key was changed after the labels were written
  (registered SHA-256 `de5981ac…`, current `6aca2dc9…`). The counting code is unchanged.
- The protocol labels an alert on a `require` line `safe` (`not_a_command_sink`). The reviewer
  instead labels it by the command calls of its module; the five such labels follow the
  reviewer.
- The first score, with the assistant's labels only, was: all sources TP 109, FP 14,
  undetermined 17; after filtering FP 13. It is superseded by the table above.

## Files

| Path | Content |
|---|---|
| `PROTOCOL.md`, `PREREGISTRATION.json` | Criteria and scoring rules fixed before the sheet was built, with hashes |
| `label_sheet.py` | Lists the items; builds the blind labeling sheet and the full review sheet from npm |
| `review_pending.py` | Builds one Markdown file with the labels no person has reviewed yet |
| `labels.json` | The 78 labels with class, reason, who assigned them and each review decision |
| `score_labels.py`, `results/score.json` | Scoring against the saved v0.3 exports and its output |

## Rebuild (no stack, no network)

```bash
python experiments/evaluation/js-labels-v0.3/score_labels.py \
  --json experiments/evaluation/js-labels-v0.3/results/score.json
```
