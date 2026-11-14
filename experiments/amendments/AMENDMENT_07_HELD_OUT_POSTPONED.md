# Amendment 07 — Postpone the held-out run to the next pipeline version

- Date: 2026-11-15; status: **adopted by the project owner; supervisor agreement pending**.
- Previous amendment: [Amendment 06](AMENDMENT_06_PRODUCT_PIPELINE_ON_PAIRS_V1.md).
- **No held-out pair has been scanned.** `evaluation/pairs-v1/held_out/` holds labels only and
  `HELD_OUT_GATE.json` does not exist.

## 1. What happened under Amendment 06

The development split was scanned once with the frozen v0.2 configuration (commit `f1e7c0c`,
`evaluation/pairs-v1/FROZEN_CONFIGURATION.json`; `freeze.py check` passed after the last scan).
All 34 pairs were acquired with the SHA-256 recorded in `pairs/sources.lock.json`: 30 scans
completed, 4 were partial. Result: `evaluation/pairs-v1/development/result.json`. This result is
development data.

## 2. Decision

While that run was in progress the owner asked for a new development phase: fixing known
JavaScript matching failures and trying a narrow filter condition for JavaScript/TypeScript.
Eight of the nine resolved held-out locations are JavaScript. On 2026-11-15 the owner therefore
decided **not to open the held-out split for v0.2** and to keep its single use for the pipeline
version that follows.

## 3. Consequences

- Section 6 of Amendment 06 (freeze between the two steps) ends here. The files it froze may
  change; `FROZEN_CONFIGURATION.json` stays as the record of what the development run used.
- The development split of pairs-v1 is now exposed development data and may inform the next
  version. Its v0.2 result is a baseline, not an independent test of any later version.
- Before the held-out split is opened, a new amendment must name the pipeline version, repeat
  the freeze (`freeze.py write`, commit, `freeze.py gate`) and be adopted by the owner. The
  question, matching rule, metrics and source check of Amendment 06 sections 2 to 5 stay in
  force unless that amendment changes them.
