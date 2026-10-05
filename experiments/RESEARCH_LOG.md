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

