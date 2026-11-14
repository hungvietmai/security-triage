# Amendment 06 — Evaluate the product pipeline v0.2 on pairs-v1

- Date: 2026-11-15; status: **adopted by the project owner; supervisor agreement pending**.
- Base protocol: v1.0.0, commit `80db12b6f7b275501f9c0f260c90cd05e818491e`.
- Previous amendment: [Amendment 05](AMENDMENT_05_RESERVE_TO_DEVELOPMENT.md).
- Split: `split_v0.2` (development 34 acquired pairs, held-out 16 pairs); unchanged.
- Repository state immediately before this amendment: `e1d1cc1`.
- **No pair of pairs-v1 has been scanned by the v0.2 pipeline when this amendment is committed**,
  except the development pair `secbench-curling-0.2.0`, whose prior exposure the manifest records.

## 1. Decision

On 2026-11-15 the project owner decided, in the working session, to evaluate the product
pipeline (`command-injection-v0.2`, `adjudicate-v0.2`) on pairs-v1 in two steps:

1. the **development split first**, as a rehearsal: its result is development data;
2. then the **held-out split, once**.

The reason for the order: two earlier checks on unseen sources each exposed an application
defect that failed a scan (line endings, an unparsable Python file). A set that can be opened
once should not carry that risk.

## 2. Question and configurations

On the vulnerable version of each pair, at the known location extracted before any scan
(`pairs/<pair>/known-locations.json`):

1. *Detection:* is the known location reported by Semgrep alone, CodeQL alone, the language
   tool alone (ESLint or Bandit), Semgrep ∪ CodeQL, and the union of all sources;
2. *Filtering:* does the filter step move a known location out of the main review list;
3. *Ranking:* how many known locations are in the first tiers (P1, P2).

Only the vulnerable version is scanned. The fixed version is not a negative label
(`pairs/README.md`), so this evaluation gives **no precision and no F1**.

## 3. Counting unit, matching rule, metrics

- Unit: the review candidate (one call).
- A known location is *reported* by a configuration when one of its candidates is in the same
  file and starts on the location's `span.startLine`. A candidate elsewhere in the file does not
  count; the start lines of such candidates are printed as a diagnostic only.
- A pair whose location is `known_location_unresolved` has no site: its candidates are counted,
  never scored.
- Metrics, computed by `evaluation/independent-secbench/configurations.py` through
  `evaluation/pairs-v1/score_pairs.py`: known locations reported per configuration, locations
  reported by one tool only, locations lost to filtering, kept locations by priority, unlabeled
  candidates by list and priority, scan time. Denominator: known locations of pairs whose scan
  completed and whose bytes were verified (section 4). Other pairs are listed with the reason.

## 4. Sources: deviation from the cache rule

`pairs/README.md` requires evaluation runs to read the locked archive cache
`artifacts/pair-sources/` and states that a new download is not a substitute for missing locked
bytes. That cache is not on the machine used for this run and no backup of it is available.

Deviation adopted here: each source is acquired by the application from the coordinate in the
pair manifest, and **a scan is accepted only when the SHA-256 the application records for the
archive equals the hash in `pairs/sources.lock.json`** (`pair_labels.py --verify`). Equal hashes
mean the scanned bytes are the locked bytes. A pair whose archive differs (GitHub regenerates
commit archives) or cannot be acquired is excluded from the scored table and reported; it is
not replaced.

## 5. Interpretation fixed in advance

- A known location that filtering removed is a **failure** of the filter step, whatever the reason.
- A known location that is not reported is a miss under the matching rule, also when a
  candidate exists on another line.
- Comparisons between configurations are descriptive; no statistical test.
- Results are reported whether favourable or not.
- Each source is scanned once. A failed or partial scan stays in the result and is not rerun.

## 6. Freeze gates

Before the first development scan, this amendment, the scoring kit, the label files of both
splits and `evaluation/pairs-v1/FROZEN_CONFIGURATION.json` are committed. That file holds the
SHA-256 of every frozen file: the profile and its language configurations, the triage code
(sink locators, reconciler, priority policy, filter rules), the detection rules, both evidence
packs, the tool pins and configurations, the scoring scripts, the label files and this
amendment.

Between the two steps, only a defect that makes scans fail or records wrong data may be fixed,
and only outside the frozen files. If the rehearsal shows that a frozen file must change, **the
held-out split is not opened** and that is reported.

Before the first held-out scan, `freeze.py gate` checks the frozen hashes again and writes
`HELD_OUT_GATE.json` with the commit id; that file and the development result are committed.

## 7. Development record for v0.2 (protocol §7)

- Development period: 2026-11-13 to 2026-11-15, by the project owner working with an AI coding
  assistant. **Active minutes were not logged**; the effort budget of §7 can therefore not be
  checked for v0.2. This is a limitation of the record.
- Development data the v0.2 filter rules and evidence packs were built and revised on: OWASP
  BenchmarkPython (CWE-78 sites), the twelve npm packages of development batches 01–03 and
  `curling@0.2.0`.
- Revision rounds of the filter step: `adjudicate-v0.1` (G1, G2), then `adjudicate-v0.2` (adds
  G3). No rule was changed after the five independent checks of 2026-11-14/15
  (`evaluation/independent*/`), whose registrations hash the same files.
- Data seen but not used to change a rule: the sources of those five checks.

## 8. Limits known in advance

- Held-out: 16 pairs, 9 with a resolved location (8 JavaScript, 1 Python). The filter step has
  evidence packs for Python only, so the held-out result says almost nothing about filtering.
- Positives only: no precision, no false-positive count.
- Known locations come from dataset metadata and patch hunks, not from independent adjudication.
- Large Python repositories may exceed the scanner time limits; such scans are reported as
  failed or partial.
- The commits that precede the scans are local. A commit orders events; it is not an external
  timestamp.
