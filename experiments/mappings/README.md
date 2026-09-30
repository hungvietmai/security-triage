# Rule claims v1 — development mapping

This mapping classifies what a rule reports, independently of whether its finding
is technically correct, in the threat model, or eligible for suppression. It is a
development implementation of the protocol's rule-to-prediction requirement;
it has not been frozen for held-out evaluation.

## Candidate contract

**Every result from the six recognized pinned rules remains a CWE-78 candidate,
including the audit rules.** Claim kind does not remove predictions. After sink
mapping and independent labeling, resolved in-scope candidates can be scored at
the protocol's common unit. Labels address the target CWE-78 assertion under the
stated assumptions, while literal correctness of an API-use warning is reported
separately. Until those steps are complete, this module emits no metrics.

An audit message can correctly describe shell usage while the call is negative
for CWE-78 exploitability. These are different judgments. It is misleading to
announce "fixing a wrong tool warning" solely because such a candidate is negative
for the experiment's vulnerability definition. Report audit workload and CWE-78
prediction performance explicitly. Do not quietly exclude audit rules from S0
when comparing it with ST/S1/Q0, or call that a precision improvement.

| Tool / canonical rule | Claim kind | Upstream category | Interpretation |
| --- | --- | --- | --- |
| Semgrep detect-child-process | conditional_argument_flow | audit | Function-argument flow to a command/executable; caller control needs review |
| Semgrep dangerous-spawn-shell | conditional_interpreter_argument | vuln | Data reaches an explicit interpreter argument; review source and semantics |
| Semgrep spawn-shell-true | shell_usage_audit | audit | Shell option observed; variable values and exploitability require separate evidence |
| Semgrep shelljs-exec-injection | conditional_wrapper_call | audit | Wrapper call with nonliteral input pattern; does not itself prove exploitability |
| CodeQL js/command-line-injection | modeled_command_line_flow | n/a | Query-modeled source-to-command flow, not a ground-truth label |
| CodeQL js/shell-command-constructed-from-input | modeled_library_command_construction | n/a | Query-modeled library-input command construction, not proof of exploitability |

Semgrep path prefixes in rule IDs are normalized only at a dot boundary; CodeQL
IDs match exactly. Known mappings require matching tool version and definition
SHA-256 in the recorded configuration. Unknown IDs or changed pins remain in the
output as `classification_unresolved`. They must remain visible in coverage and
review ledgers and cannot silently disappear from a future metric denominator.

## Output fields and provenance

`rule_semantics` is additive. It records mapping version/digest, canonical rule ID,
claim kind, upstream category, role hint, candidate status and separate CWE lists:
`reported_cwes_normalized` versus `mapped_rule_cwes`. Original metadata and raw
SARIF are preserved. `cwe_links` points to the canonical MITRE definition pages.
Multiple CWE tags remain multiple tags; this is not CWE-78/88 adjudication.

`focus_role_hint` describes the rule template. It is not an AST-confirmed argument
role or a sink identity. The annotator neither creates canonical location units
nor resolves aliases, scope, truth labels or taint feasibility.

The CLI verifies the stored configuration and every available SARIF against the
run report's hashes, then reuses the existing SARIF parser. Completed runs missing
SARIF fail; unsuccessful runs missing SARIF retain unavailable counts, not zero.
It creates a fresh derived raw ledger and does not modify any human review or
approved-label file. The lower-level `annotate` function preserves supplied fields,
including labels. Checksums establish consistency with the supplied run report,
not authenticity against an attacker who can replace the entire evidence bundle.

## Use

```bash
python -m experiments.annotate_claims \
  --run-directory artifacts/your-recorded-run \
  --output artifacts/your-recorded-run-claims.json
```

The input directory contains `run.json`, `config.json` and recorded scanner SARIF.
The output must be new. Archived evidence can be decoded to that same layout;
verify the envelope and inner file hashes before using it. No scanner, dependency
installation, rule tuning or suppression is performed by this command.

Current results: [eight-package annotation report](../reports/rule-claims-v1/REPORT.md).
