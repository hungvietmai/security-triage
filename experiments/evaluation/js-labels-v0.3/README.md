# Labels for the JavaScript candidates of v0.3 (CWE-78)

Every JavaScript or TypeScript candidate that profile `command-injection-v0.3` reports on the
84 npm sources of [../js-matching-v0.3/](../js-matching-v0.3/README.md) has a label:
`vulnerable`, `safe` or `undetermined`. The criteria were fixed first
([PROTOCOL.md](PROTOCOL.md), hashes in [PREREGISTRATION.json](PREREGISTRATION.json)); nothing
was rescanned.

## Who assigned and who reviewed the labels

- **An AI coding assistant proposed every label by reading the package source**, at the
  owner's request (2026-11-15). The same assistant wrote the locator and filter rule G4 that
  are being measured.
- **The project owner reviewed all of them on 2026-11-15**, each with its code:
  - 31 labels (every one the assistant had proposed as `safe` or `undetermined`) in an
    interactive session; the owner changed 12 (10 labels, 2 classes);
  - 47 labels proposed as `vulnerable` in a Markdown review file; the owner agreed with 44 and
    held 3 until the start line of each alert was shown from the saved report, then confirmed
    them and split one into seven units.
- Each decision and the owner's note are in the `review` field of [labels.json](labels.json).
- Limits that remain: one reviewer, who is the project owner and saw the assistant's proposal
  and reason for each item; the 84 sources are development data of v0.3.

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
| `extra-asciinema` `index.js`, seven unmatched alerts | one vulnerable unit | **seven vulnerable units**, one per alert start line (31, 35, 40, 41, 42, 43, 45) |

The CVE identifiers and source links in the notes are the reviewer's; the three CVEs from 2026
were looked up and exist for those packages.

## Result

146 units: 62 known vulnerable sites (CVE labels) and 84 reviewed labels (60 vulnerable,
11 safe, 13 undetermined). Seven more known sites have no candidate.

| Configuration | TP | FP | Undetermined | FN | Precision | Recall ≤ | F1 ≤ |
|---|---:|---:|---:|---:|---:|---:|---:|
| Semgrep alone | 52 | 4 | 9 | 77 | 0.93 | 0.40 | 0.56 |
| CodeQL alone | 98 | 2 | 1 | 31 | 0.98 | 0.76 | 0.86 |
| ESLint alone | 83 | 9 | 6 | 46 | 0.90 | 0.64 | 0.75 |
| Semgrep ∪ CodeQL | 109 | 4 | 10 | 20 | 0.96 | 0.85 | 0.90 |
| All sources | 122 | 11 | 13 | 7 | 0.92 | 0.95 | 0.93 |
| All sources, after filtering | 122 | 10 | 13 | 7 | 0.92 | 0.95 | 0.93 |
| First tiers (P1+P2), after filtering | 97 | 4 | 9 | 32 | 0.96 | 0.75 | 0.84 |

- **Filter step:** 1 safe unit filtered (rule G4, `arpping` `index.js:60`), 0 vulnerable,
  0 undetermined.
- **Safe units left in the review list: 10.** By class: 6 `validated_or_escaped`,
  2 `internal_values_only`, 1 `constant_command` (`git-parse` `dist/git_pull.js`: the call was
  not located, so G4 had nothing to act on), 1 `no_shell`. By priority: P1 2, P2 2, U 2, P3 4.
- 25 vulnerable units are outside P1 and P2: 13 in P3 and 12 in queue U.

Full output: [results/score.json](results/score.json).

## What this supports and what it does not

- The review list for JavaScript is mostly true positives (122 of 133 decided units), so the
  room for removing false positives is small: 11 units.
- The filter step removes 1 of those 11 and no true positive. **It does not reduce the other
  10**; that is the measured answer for false positives outside the constant-command class.
- Most of the 10 need evidence the pipeline does not have: a value validated or escaped before
  use (6), a command built from values the package itself sets (2), a call without a shell (1).
- **Matching gap found by the review:** in `git-parse` the calls `exec(...)` on
  `dist/checkout_commit.js:34` and `dist/git_diff.js:22` are vulnerable and no tool located
  them (Babel interop `_child_process.default.exec` wrapped by a promisify helper). The only
  trace is ESLint's alert on the `require` line, kept in queue U. Queue U holds 12 vulnerable
  units and 2 safe ones, so it must stay in the review list.
- Recall and F1 are upper bounds: the denominator has only vulnerable locations that a tool or
  a CVE points at.
- A unit is an entry of the review list, not a distinct vulnerability: the seven unmatched
  alerts of `extra-asciinema` concern the two calls on lines 71 and 99, which are units too.
- 13 units are `undetermined`, most of them packages whose purpose is to run the caller's
  command (`shelljs`, `grunt-shell`, `gulp-shell`, `release-it`, ...). They count neither way.

## Deviations from the registered files

- `score_labels.py` failed on its first run: sorting units raised `TypeError` for unmatched
  alerts, which have no line. One sort key was changed after the labels were written.
- The registered scripts merged all unmatched alerts of one file into one unit. At the
  reviewer's decision each unmatched alert is its own unit, identified by the line it starts on
  (`U<line>` in the label id). `label_sheet.py` and `score_labels.py` were changed for this;
  the counting code is otherwise unchanged. Registered and current SHA-256: `label_sheet.py`
  `d78f9416…` → `f5de4b06…`, `score_labels.py` `de5981ac…` → `bc056bde…`.
- The protocol labels an alert on a `require` line `safe` (`not_a_command_sink`). The reviewer
  instead labels it by the command calls of its module; the five such labels follow the
  reviewer.
- Earlier scores, superseded by the table above: with the assistant's proposals only, all
  sources TP 109, FP 14, undetermined 17 (140 units); after the review of the first 31 labels,
  TP 116, FP 11, undetermined 13 (140 units).

## Files

| Path | Content |
|---|---|
| `PROTOCOL.md`, `PREREGISTRATION.json` | Criteria and scoring rules fixed before the sheet was built, with hashes |
| `label_sheet.py` | Lists the items; builds the blind labeling sheet and the full review sheet from npm |
| `review_pending.py` | Builds one Markdown file with the labels no person has reviewed yet (none at present) |
| `labels.json` | The 84 labels with class, reason, who proposed them and each review decision and note |
| `score_labels.py`, `results/score.json` | Scoring against the saved v0.3 exports and its output |

The review file the owner marked is `artifacts/js-labels-v0.3/REVIEW_VULNERABLE_47.md` (ignored
by git); its decisions and notes were copied into `labels.json`.

## Rebuild (no stack, no network)

```bash
python experiments/evaluation/js-labels-v0.3/score_labels.py \
  --json experiments/evaluation/js-labels-v0.3/results/score.json
```
