# Research publication log

This log records externally visible research-methodology freezes and publication evidence.

## 2026-10-05 — Amendment 03: command-injection family scope

- Amendment: `experiments/amendments/AMENDMENT_03_COMMAND_INJECTION_FAMILY.md`
- Adoption commit: `67ef4e4c1d94f71eac6ffcee06ffff353bb8790f`
- Commit URL: https://github.com/hungvietmai/security-triage/commit/67ef4e4c1d94f71eac6ffcee06ffff353bb8790f
- Tag: `amendment-03`
- Tag URL: https://github.com/hungvietmai/security-triage/tree/amendment-03
- Verified tag target: `67ef4e4c1d94f71eac6ffcee06ffff353bb8790f`
- GitHub-recorded publication evidence time: `2026-10-05T04:38:26Z`
  (`2026-10-05T11:38:26+07:00`)
- Publication evidence: GitHub Actions run
  https://github.com/hungvietmai/security-triage/actions/runs/37264396502
- Workflow conclusion: `success`; the temporary tag-publishing workflow was
  removed after the tag target was verified.
- Pre-scan declaration: no new vulnerability-pair scan result had been produced
  or inspected after Amendment 02 and before the Amendment 03 adoption commit.
- Scope change: the primary command-injection family is CWE-77/CWE-78/CWE-88,
  while results remain separately reported by CWE. CWE-77 is eligible only when
  the vulnerable sink performs or initiates OS process/command execution under
  the frozen Linux/POSIX threat model; other CWE-77 interpreter cases are
  excluded from the primary scope with a recorded reason.

## 2026-10-05 — split-v0: deterministic language-stratified split

- Split artifact: `experiments/inventory/split_v0.json`
- Split generator: `experiments/make_split.py`
- Freeze commit: `72972469ea7b8da895ba4a3bdc2309676b04a953`
- Commit URL: https://github.com/hungvietmai/security-triage/commit/72972469ea7b8da895ba4a3bdc2309676b04a953
- Tag: `split-v0`
- Tag URL: https://github.com/hungvietmai/security-triage/tree/split-v0
- Verified tag target: `72972469ea7b8da895ba4a3bdc2309676b04a953`
- GitHub-recorded publication evidence time: `2026-10-05T06:59:16Z`
  (`2026-10-05T13:59:16+07:00`)
- Publication evidence: GitHub Actions run
  https://github.com/hungvietmai/security-triage/actions/runs/37275228419
- Split-generation evidence: GitHub Actions run
  https://github.com/hungvietmai/security-triage/actions/runs/37275106036
- Workflow conclusion: `success`.
- Unit of split: `group_id`; stratification is by language only.
- Hash rule: ascending SHA-256 of UTF-8 `group_id`; the first
  `ceil(40% * fresh eligible groups)` in each language are held out.
- JavaScript: 21 fresh eligible groups -> 9 held out and 12 development;
  with two previously exposed groups, total development is 14. Twelve groups
  are reserve and twelve are excluded.
- Python: 27 fresh eligible groups -> 11 held out and 16 development.
- Total held-out groups: 20.
- `cwe_unresolved` and non-primary CWE groups are reserve; pre-existing
  exclusions remain excluded. Explicit future `scope_verdict=out_of_scope`
  is excluded and `scope_verdict=unresolved` is reserve.
- No new Semgrep/CodeQL pair scan was run to create or inspect this split.

## 2026-10-05 — Amendment 04: pre-scan OS-command scope review

- Amendment: `experiments/amendments/AMENDMENT_04_SCOPE_REVIEW.md`
- Adoption commit: `f6243fa36784ecc88af2259bedc2b121a25f357d`
- Commit URL: https://github.com/hungvietmai/security-triage/commit/f6243fa36784ecc88af2259bedc2b121a25f357d
- Tag: `amendment-04`
- Tag URL: https://github.com/hungvietmai/security-triage/tree/amendment-04
- Verified tag target: `f6243fa36784ecc88af2259bedc2b121a25f357d`
- GitHub-recorded publication evidence time: `2026-10-05T08:25:58Z`
  (`2026-10-05T15:25:58+07:00`)
- Publication evidence: GitHub Actions run
  https://github.com/hungvietmai/security-triage/actions/runs/37283590108
- Workflow conclusion: `success`.
- Scope correction: the Linux/POSIX OS-process/command-execution sink condition
  now applies to CWE-77, CWE-78 and CWE-88.
- Scope review must use advisory/patch evidence without Semgrep/CodeQL output.
- Out-of-scope or unresolved held-out groups are not replaced, and split-v0 is
  not redrawn.
- No new vulnerable-pair Semgrep/CodeQL scan had been produced or inspected
  before adoption of this amendment.

## 2026-10-05 — Scope review v0 and split-v0.1

- Scope amendment: `experiments/amendments/AMENDMENT_04_SCOPE_REVIEW.md`
- Scope review commit: `246b46959c00e28bfc24dc3e2e62b265095bc995`
- Scope review artifact: `experiments/inventory/scope-review-v0.json`
- Human-readable scope report: `experiments/inventory/SCOPE_REVIEW_V0.md`
- Scope-evidence collection run:
  https://github.com/hungvietmai/security-triage/actions/runs/37284347406
- Scope review used advisory/fix-patch evidence only; no Semgrep/CodeQL pair
  output was used.
- Usable groups reviewed: **62**.
  - JavaScript: 34 in scope, 1 out of scope.
  - Python: 15 in scope, 12 out of scope.
- Mixed repository groups retained because they contain at least one in-scope
  pair row: `pyvul:mlflow/mlflow` and `pyvul:paddlepaddle/paddle`.
  Out-of-scope pair rows inside those groups are excluded from the primary
  denominator.

### split-v0.1 freeze

- Split artifact: `experiments/inventory/split_v0.1.json`
- Corrected split generator: `experiments/make_split.py`
- Freeze commit: `67f77a381ba2be64b9686f046715223bb508c46c`
- Commit URL: https://github.com/hungvietmai/security-triage/commit/67f77a381ba2be64b9686f046715223bb508c46c
- Tag: `split-v0.1`
- Tag URL: https://github.com/hungvietmai/security-triage/tree/split-v0.1
- Verified tag target: `67f77a381ba2be64b9686f046715223bb508c46c`
- GitHub-recorded publication evidence time: `2026-10-05T08:47:41Z`
  (`2026-10-05T15:47:41+07:00`)
- Tag publication evidence:
  https://github.com/hungvietmai/security-triage/actions/runs/37285860127
- Split verification/test run:
  https://github.com/hungvietmai/security-triage/actions/runs/37285579232
- The verification run confirmed that regenerated split-v0 is identical to the
  frozen split-v0 artifact before deriving v0.1.
- Test status: **31 experiment tests passed** (27 existing tests + 4 new split
  reproducibility/idempotence tests).
- `prior_exposure` is now an immutable input separate from generated `split`.
- `make_split.py --check` compares split-v0 without mutating the inventory.
- split-v0.1 is derived from frozen split-v0 by scope filtering only:
  `selection_redrawn=false`, `replacement_performed=false`.

Final effective group counts:

- JavaScript: 14 development, 9 held out, 11 reserve, 13 excluded.
- Python: 9 development, 6 held out, 12 excluded.
- Pooled held-out groups after scope review: **15**.
- Removed from frozen held-out without replacement:
  `pyvul:autogluon/autogluon`, `pyvul:pytorch/pytorch`,
  `pyvul:snowflakedb/snowflake-connector-python`,
  `pyvul:tankywoo/simiki`, and `pyvul:tensorflow/tensorflow`.
- Remaining held-out groups by in-scope CWE:
  - JavaScript: CWE-77 = 4, CWE-78 = 5.
  - Python: CWE-77 = 1, CWE-78 = 4, CWE-88 = 1.
- The pooled held-out total remains above the Amendment 02 minimum, but the
  Python held-out stratum is too small for a strong Python-specific
  effectiveness claim.
- No new vulnerable-pair Semgrep/CodeQL scan was run before this freeze.



## 2026-10-05 — Post-refactor real-scanner reproducibility check

- Verification candidate commit:
  `965ccc489be21842e5c7971db49ac09e99f55240`.
- GitHub Actions evidence:
  https://github.com/hungvietmai/security-triage/actions/runs/37297668652
- GitHub-recorded run time: `2026-10-05T10:36:34Z`
  (`2026-10-05T17:36:34+07:00`); workflow conclusion: `success`.
- The workflow checked out the candidate commit explicitly, built
  `experiments/Dockerfile`, and ran `curling@0.2.0` with the image's real
  Semgrep 1.178.0 and CodeQL 2.27.1 toolchains. Scanner functions were not
  replaced with test doubles.
- Smoke result: Semgrep = **0** raw findings, CodeQL = **6** raw findings,
  total = **6**, matching the recorded pre-refactor development result.
- `findings.json` was byte-identical to the pre-refactor Step 1 baseline.
- The generated `run.json` contained `runner_files_sha256` entries for all
  **9** runner files (the CLI plus eight `app/scanners` Python files).
- The same workflow verified the documented native commands with
  `PYTHONPATH` explicitly removed and passed the full **31-test** experiment
  suite using the CI command
  `PYTHONPATH=backend python -m unittest discover -s experiments -p 'test_*.py' -v`.
- This is a development reproducibility/integration check on the already exposed
  curling case. It is not a new held-out vulnerability-pair result and does not
  change the frozen split or evaluation claims.


## 2026-10-06 — Reconciliation v0 wired into the experiment CLI

- Verification branch head before this log entry:
  `4616e5f847e295f925873be9704b68e291b6111b`.
- GitHub Actions evidence:
  https://github.com/hungvietmai/security-triage/actions/runs/37425469495
- GitHub-recorded run start: `2026-10-06T06:44:40Z`
  (`2026-10-06T13:44:40+07:00`); conclusion: `success`.
- The verified Docker image ran the real pinned Semgrep and CodeQL toolchains on
  development case `curling@0.2.0`, then ran `sink-locator-v0` and
  `reconcile-v0`.
- Raw scanner preservation check: the generated `findings.json` was
  byte-identical to the Step 1 pre-refactor baseline.
- Raw result count remained **6**: Semgrep **0**, CodeQL **6**.
- Reconciliation output: `units.json` contained exactly **1** canonical unit:
  - `unit_id = 58114fb901d995f4d95d948c211ef89b82117648db9a34447f2d5fc7e48dfdcb`
  - `sink_kind = child_process.exec`
  - `argument_role = shell_command`
  - all **6** CodeQL raw findings mapped to this unit.
- The run recorded **15** runner hashes: the CLI, eight `app/scanners/*.py`
  files, five `app/triage/*.py` files, and
  `experiments/locators/sink-locator-v0-javascript.yaml`.
- Verification quality gates in the same workflow:
  **122 backend tests passed**, backend coverage **90.36%**, and all
  **31 experiment tests passed**.
- No database write was introduced. `units.json` is a sidecar artifact and the
  raw finding ledger remains unchanged.
- This is a development integration/reproducibility check on an already exposed
  case. It does not add a held-out result or change the frozen split.


## 2026-10-06 — Day 3 reconciliation acceptance completed

- Acceptance PR: https://github.com/hungvietmai/security-triage/pull/1
- Verification workflow: https://github.com/hungvietmai/security-triage/actions/runs/37427597888
- Squash merge commit: `3929776ddf00136e890827023535a2e669b53bb8`.
- Reconciliation specification remained historically prior to implementation:
  `b295c5572cb3091682a637a37d1a161d93489c11` (specification) precedes
  `825229568d6cce3b2653d3ba936abe513b38769a` (locators) and
  `4b2e839f17eb7b40ea3dd731bbe1b597eea1ed61` (reconciler/CLI).
- The experiment CLI now enforces raw-finding conservation as a runtime
  postcondition: every raw finding ID must occur exactly once across reconciled
  units; loss or duplication fails the run.
- Experiment suite: **33 tests passed** (31 prior tests plus 2 conservation
  tests).
- Real pinned Docker scanner verification on `curling@0.2.0`:
  - baseline: **6 raw findings -> 1 canonical unit**;
  - baseline unit ID:
    `58114fb901d995f4d95d948c211ef89b82117648db9a34447f2d5fc7e48dfdcb`;
  - baseline `findings.json` was byte-identical to the Step 1 baseline;
  - paired direct-alias control: Semgrep **1** + CodeQL **6** = **7 raw
    findings -> 1 canonical unit**;
  - paired unit used the same approved unit ID and recorded
    `tools = ["codeql", "semgrep"]`;
  - all 7 paired raw finding IDs were retained exactly once.
- Backend quality gates in the same CI workflow:
  - **122 backend tests passed**;
  - branch coverage **90.36%** (required floor 90%);
  - Ruff check and format check passed;
  - strict mypy passed with no issues in 80 source files;
  - Alembic `downgrade base` then `upgrade head` completed successfully,
    followed by a clean `alembic check`.
- Historical Semgrep-only direct-alias evidence/configuration was preserved;
  the paired integration control was added as a separate development config.
- No database write was introduced by reconciliation. No held-out case was
  opened or rescanned for this acceptance check.


## 2026-10-06 — reconcile-v0.1 corrective acceptance

- Specification amendment commit:
  `deb901594954930114c215d4e9792eefc7f39615`, committed before corrective code.
- Corrective implementation head verified by CI:
  `314adc5219acdacde8526434686964f5fea5292d`.
- GitHub Actions evidence:
  https://github.com/hungvietmai/security-triage/actions/runs/37435211454
- Reconciliation integration job conclusion: **success**.
- The pinned Docker image ran the real scanners on the already exposed
  `curling@0.2.0` development case after the reconcile-v0.1 role fixes.
- Baseline result remained **6 raw findings -> 1 canonical unit**; the paired
  direct-alias control remained **7 raw findings -> 1 canonical unit** with
  `tools = ["codeql", "semgrep"]`.
- `findings.json` remained byte-identical to the Step 1 baseline.
- The canonical curling unit ID did not change:
  `58114fb901d995f4d95d948c211ef89b82117648db9a34447f2d5fc7e48dfdcb`.
- Raw-finding conservation remained satisfied for both configurations.
- Final substantive pre-merge head `40fa9ba1c433ed263671f4dd99bb2a96266daf7b` was re-verified by CI run #108 (`37438072270`): all four jobs succeeded; PostgreSQL migration verification completed `alembic check -> downgrade 0003 -> 0002 -> 0001 -> base -> upgrade head -> alembic check`, with **172 backend tests passed**, **92.93%** coverage, clean Ruff/mypy/dependency audit, and unchanged curling reconciliation acceptance.
- This corrective acceptance changes role resolution only where reconcile-v0
  was semantically wrong or over-confident. It does not redraw the frozen split,
  inspect a new held-out case, or change the canonical unit key.


## 2026-10-07 — preserved reconciliation commit-order evidence

PR #1 and PR #2 were squash-merged, so the intermediate specification and
implementation commits are not ancestors of `main`. To keep the cited research
history reachable independently of the merged PR branches, permanent evidence
refs were created at the exact historical commits:

- `evidence/reconcile-v0-spec` ->
  `b295c5572cb3091682a637a37d1a161d93489c11`
- `evidence/reconcile-v0-locators` ->
  `825229568d6cce3b2653d3ba936abe513b38769a`
- `evidence/reconcile-v0-implementation` ->
  `4b2e839f17eb7b40ea3dd731bbe1b597eea1ed61`
- `evidence/reconcile-v0.1-spec` ->
  `deb901594954930114c215d4e9792eefc7f39615`
- `evidence/reconcile-v0.1-implementation` ->
  `314adc5219acdacde8526434686964f5fea5292d`

Each evidence ref was compared with its target SHA and reported as identical
(0 commits ahead, 0 behind). These refs are intentionally separate from the
working PR branches and must not be deleted during ordinary branch cleanup.

For future research-significant specification, policy, or freeze changes, retain
the specification commit as a durable evidence ref before squash-merging, or
prefer a normal merge commit so the specification-before-implementation order
remains directly reachable from `main`.
