# Amendment 08 — Open the held-out split of pairs-v1 for pipeline v0.3

- Date: 2026-11-15; status: **adopted by the project owner; supervisor agreement pending**.
- Previous amendment: [Amendment 07](AMENDMENT_07_HELD_OUT_POSTPONED.md).
- Repository state immediately before this amendment: `9150679`.
- **No held-out pair has been scanned when this amendment is committed.**

## 1. Decision

Amendment 07 kept the single use of the held-out split for the pipeline version that followed
v0.2. That version exists: profile `command-injection-v0.3` with `adjudicate-v0.3`, the
JavaScript sink locator v1 and the worker-controlled Semgrep target selection. On 2026-11-15
the owner decided to open the held-out split for v0.3, after a rehearsal of v0.3 on the Python
pairs of the development split (the JavaScript pairs of that split were already rescanned with
v0.3 in `evaluation/js-matching-v0.3/`).

## 2. What stays from Amendment 06

Sections 2 to 5 of [Amendment 06](AMENDMENT_06_PRODUCT_PIPELINE_ON_PAIRS_V1.md) apply unchanged:
the question, the configurations compared, the counting unit, the matching rule, the metrics,
the acceptance of a scan only when its archive SHA-256 equals the hash in
`pairs/sources.lock.json`, and the interpretation fixed in advance. In particular:

- only the vulnerable version of each pair is scanned, once; a failed or partial scan stays in
  the result and is not rerun;
- a known location that filtering removed is a failure of the filter step;
- the result is coverage of known vulnerable locations. It gives no precision and no F1.

## 3. Rehearsal and freeze

1. v0.3 is run once on the nine acquired Python development pairs
   (`evaluation/pairs-v1/development-v0.3-python/`). Its purpose is to expose defects that make
   scans fail or record wrong data. Its result is development data.
2. A defect found there may be fixed only outside the frozen files. If a frozen file must
   change, the held-out split is not opened and that is reported.
3. `evaluation/pairs-v1/FROZEN_CONFIGURATION_v0.3.json` records the SHA-256 of every frozen
   file: the v0.3 profile and the policy and claim files it refers to, the triage code, the
   Semgrep adapter (target selection), the detection rules, the sink locator v1, both evidence
   packs, the tool pins and configurations, the scoring scripts, the held-out label file and
   Amendments 06 and 08. It is committed together with this amendment and the rehearsal result.
4. Immediately before the first held-out scan, `freeze.py gate` checks those hashes again and
   writes `HELD_OUT_GATE.json` with the commit id; that file is committed before the scan.

## 4. Development record for v0.3 (protocol §7)

- Development period: 2026-11-15, by the project owner working with an AI coding assistant.
  **Active minutes were not logged.**
- Data v0.3 was built and revised on: the saved v0.2 exports of 84 npm sources (the second
  independent check, the development npm batches and the JavaScript pairs of the pairs-v1
  development split); ten of those packages were read. One revision round of the locator
  followed the first v0.3 run on those sources (a regression on renamed destructuring).
- The held-out manifests, labels and known locations were prepared before any scan (pairs
  README) and were not consulted while v0.3 was built.

## 5. Limits known in advance

- 16 pairs, 9 with a resolved location: 8 JavaScript, 1 Python. Too few for a rate; the result
  is reported as counts.
- Positives only. The filter rules can only be seen not to remove a known location; their
  benefit cannot be measured here.
- After this run the held-out split is exposed and cannot serve a later version.
- The commits that precede the scans are local. A commit orders events; it is not an external
  timestamp.
