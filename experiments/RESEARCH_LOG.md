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
