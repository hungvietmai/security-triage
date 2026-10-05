# Evaluation protocol — Security Triage

> Development update (2026-10-05): [Amendment 01](amendments/AMENDMENT_01_QT.md)
> changes the primary method to QT and adds Q1, review procedures and ordered
> gates. It takes precedence on those points. Supervisor agreement is pending.
> The v1.0.0 text below is retained so earlier results keep their interpretation.

- Protocol version: **1.0.0**
- Adopted: **2026-09-28**
- Status: **pilot protocol; no held-out evaluation has run under this protocol**.
- Primary method: Semgrep screening followed by evidence-based CodeQL adjudication.
- Initial research scope: CWE-78, JavaScript and Python, Linux/POSIX.
- TypeScript, additional CWEs and a union-input policy are conditional extensions.

This protocol takes precedence over earlier experiment planning notes where they
conflict. It specifies evaluation, not implemented scanner capabilities or achieved
results. The hypotheses may fail. Existing application CI is not research evidence.

## 1. Questions and configurations

H1: Does adjudication remove false positives from Semgrep while retaining known
true vulnerability locations? H2: Does it improve on simply tuning Semgrep rules?
H3: Does Semgrep contribute useful detections beyond CodeQL on these cases?

All configurations use the same CLI, acquisition layer, raw-result store,
normalizer, location mapping and evaluator. Adapters are reusable by FastAPI/Celery.

| ID | Configuration | Candidate set and decision |
|---|---|---|
| S0 | Original Semgrep | Pinned, appropriate CWE-78 rules; no pilot-specific tuning |
| Q0 | Original CodeQL | Pinned target queries and models; same source snapshot |
| ST | Semgrep + adjudication | S0 candidates; retain supported and inconclusive; suppress proposed_reject |
| S1 | Tuned Semgrep | Rule changes made only on development data within the budget |

Q0 findings outside S0 remain baseline results, not primary ST output. With fixed
mapping, ST is a subset of S0; ST recall cannot exceed S0 recall. A configuration
that is not implemented is recorded as unavailable, never copied from another run.

Post-processing reports, reusing stored scanner results:

- S0 with evidence links but no suppression: normalization/linking control.
- U0 = S0 union Q0 after location reconciliation: simple-union baseline.
- ST-sensitive: retain supported only; report lost TPs as well as FP reduction.
- Four-way partition for S0/Q0: Semgrep-only, CodeQL-only, both, neither. The
  neither group is defined over independently known vulnerable locations K;
  unmatched findings remain in the unresolved mapping ledger.

S0 versus ST isolates the primary policy effect; S0/Q0 versus U0 measures
complementarity. U0 versus ST changes both candidates and filtering and cannot
isolate adjudication. Union-plus-policy is an optional separate configuration.

## 2. Acquisition, population and splits

Start with one real development case from SecBench.js; aim for five JavaScript and
five Python vulnerability groups for feasibility, not statistical sufficiency.
Package source at the vulnerable version is scanned, not only the exploit test.
CVEfixes and independently reviewed advisories/patches are candidate real-world
sources. Synthetic fixtures and deliberately vulnerable applications are development
resources; report benchmark and real-project results separately.

Each case manifest records case_id, group_id, source_kind, language, source URL,
full resolved commit or exact package version, artifact checksum, source root,
reference provenance, acquisition status and exclusions. Preserve artifact bytes.
Ground-truth sink locations and verdicts live in a separate label file, not scanner
configuration. Scan scope cannot be restricted to advisory locations.

Maintain an inventory: candidate -> acquired -> scope assessed -> labeled ->
analysis attempted/completed. Record exclusion reasons, extraction failures,
timeouts and partial outcomes. Do not silently remove difficult cases.

Assign entire repositories/vulnerability families (including patched versions,
forks and near-duplicates) to the same split. For the ten-group pilot target,
reserve three groups per language for development and two for a pilot check,
before seeing scanner outcomes. Missing groups produce an explicitly incomplete
pilot; do not substitute groups because their results are unfavorable.

The pilot check is opened once after configuration freeze. If its results inform
changes, it is thereafter exploratory/development evidence; a fresh independent
set is needed for the revised method's final evaluation. Final sample size and
language coverage are determined from inventory and label feasibility before
final held-out execution, not inferred from the ten-group target.

## 3. Evaluation units and CWE classification

CWE is **not part of the location identity**. Use this canonical identity:

    snapshot_id + normalized_relative_path + sink_anchor + argument_role

sink_anchor identifies a particular call/execution site, preferably by AST span;
argument_role distinguishes the relevant executable/command/argument expression.
Different source-to-sink paths into the same unit do not multiply detected sites.
Store reported_cwes per raw finding and adjudicated_cwes as versioned label
attributes. Keep original tool IDs, messages, spans and evidence. A CWE correction
changes classification attributes, not the identity of the source location.

Within this single-CWE experiment, each unit's primary technical label addresses
CWE-78 under documented assumptions. A site containing only CWE-88 may be false
for the CWE-78 claim while still security-relevant: retain its CWE-88 label and
report it separately. A CWE-88-only tool finding is included in acquisition/review
but does not count as a predicted CWE-78 finding unless the predeclared mapping
or the tool explicitly claims CWE-78. Resolve broad/multiple-CWE rules using a
versioned mapping before test execution; unresolved classification is reported.

Do not infer CWE-88 or safety merely from shell=False or list arguments. Executable
semantics, explicit interpreters and argument interpretation require evidence.
CWE-78/88 reclassification is a secondary report, not a hidden expansion of scope.
A future multi-CWE evaluation must define per-CWE prediction/label attributes
without changing the underlying location IDs.

### 3.1 Mapping and unanchored findings

Normalize paths against the immutable snapshot and retain original coordinates.
Use explicit sink evidence/AST linkage; same file, nearby line or matching CWE
alone is insufficient to merge findings. Record mapping algorithm/version and
manual mapping evidence. A raw alert covering several sinks may map to several
units only with explicit evidence; it is still one raw alert for workload metrics.

Every finding enters a ledger. If it cannot be mapped to a sink, create a fallback:

    snapshot_id + reported_path + reported_region + fallback_discriminator

Merge fallback records only when equivalence is demonstrated using fixed rules.
Otherwise retain separate records; use raw run/result identity as discriminator
when even location is missing. Tool provenance may identify a fallback record but
is not evidence for its truth label. Never discard an alert because mapping fails.

Review fallback records under the same labeling policy. A confirmed false
CWE-78 assertion at an in-scope fallback unit contributes FP_location. A confirmed
true fallback contributes TP_location if its vulnerability identity can be
established independently. Resolve aliases to known sites before scoring; if the
site identity or duplicate relation remains ambiguous, report mapping-unresolved
and exclude it from point estimates with explicit coverage counts. Never invent
new true sites just to award detection credit. Include such records in alert-level
review/workload reporting and, where feasible, sensitivity bounds.

Freeze a common evaluation ledger across configurations. Mapping corrections made
after review apply to every configuration; log changes, do not tune a matcher for
one tool's advantage. Report automatic sink-match coverage, final reviewed coverage,
and unresolved counts, per configuration and overall. The automatic unmatched
rate is raw findings without a sink assignment / raw findings (N/A for zero).

## 4. Labels, threat model and review

Two separate fields are required for each evaluation unit:

    technical_verdict: true_positive | false_positive | unresolved
    scope_verdict: in_scope | out_of_scope | unresolved

Also store adjudicated_cwes, assumptions, evidence references, reviewer,
review timestamp, label version and threat_model_version. Vulnerability labels
for K sites with no alerts use the same location ledger. technical_verdict refers
to the target CWE claim, not whether the repository has any security issue.

Initial threat model: Linux/POSIX, attacker-controlled input at modeled application
boundaries or public package APIs, trusted installed executable/environment unless
explicitly modeled otherwise. Initial evidence support covers Node exec/execSync,
Python os.system and subprocess run/Popen with shell=True. Distinguish **research
scope** from **analyzer modeling coverage**: an in-scope wrapper may lack a model;
that creates inconclusive evidence, not an out_of_scope label. Scope decisions
come from the frozen research definition, not a tool's success or failure.

| Technical verdict | Scope | Scoring if configuration predicts the unit |
|---|---|---|
| true_positive | in_scope | TP_location |
| false_positive | in_scope | FP_location |
| either resolved verdict | out_of_scope | Separate report, outside main numerator and denominator |
| unresolved | any | Label-unresolved ledger; report coverage |
| any | unresolved | Scope-unresolved ledger; report coverage |

Policy inconclusive is not label unresolved: a retained inconclusive prediction
counts TP or FP whenever independent labels are resolved. Failure is not a negative
prediction. A missing CWE-78 path is not a false-positive label. Patch status is
not a blanket negative label for a repository.

Review the **union of every frozen configuration's findings**, plus independently
known vulnerable locations, not only S0/Q0 output. Review source/advisory/patch
context; hide tool/configuration identity and policy verdict where feasible.
Record when blinding is incomplete. Seek independent second review for all
proposed suppressions and a deterministic 20% sample of other resolved units
(sorted unit ID, every fifth unit). If no second reviewer is available, flag those
labels as single-reviewer and disclose it; do not fabricate agreement. Resolve
reviewer disagreements or retain unresolved.

## 5. K, N, G and the common scoring universe

K: independently confirmed, in-scope CWE-78 sites frozen before examining
held-out scanner output. N: additional in-scope true sites confirmed during
review. Tag N discovery provenance (pooled alert, manual incidental discovery,
other independent reference). G = K union N after alias reconciliation.

G retains sites in K missed by every tool. Its pooled portion N is biased toward
the participating configurations. Report K/N counts and results separately;
expanded recall is not a claim of exhaustive real-world recall. Newly confirmed
sites are included for **all** configurations, including those that missed them.

Let F be the common set of resolved, in-scope false CWE-78 prediction units from
the union of configurations. The scorable universe is E = G union F. For each
configuration c, let P_c be its predicted canonical units intersected with E:

    TP_c = |P_c intersect G|
    FP_c = |P_c intersect F|
    FN_c = |G minus P_c|
    Precision_location = TP_c / (TP_c + FP_c)
    Recall_expanded    = TP_c / (TP_c + FN_c)
    F1_location       = 2*TP_c / (2*TP_c + FP_c + FN_c)
    Recall_independent = |P_c intersect K| / |K|

F1 uses the expanded universe and is explicitly labeled pooling-sensitive.
Do not combine expanded precision with independent recall into another F1.
Precision with zero predictions is N/A; recall on an empty truth set is N/A;
direct-form F1 is zero if G is nonempty and no predictions exist, and N/A when
its denominator is zero. Report underlying counts alongside every ratio.

Report FP reduction versus S0 and versus S1 (N/A if baseline FP=0), true alerts
suppressed, true locations completely lost, inconclusive rates, unresolved label/
scope/mapping rates, acquisition/analysis failures and review workload. Raw/deduped
alert precision may be supplementary with explicit units; it is not used in the
location F1. Do not claim FPR unless the negative universe/TN is defined.

Point estimates describe resolved eligible units only. Publish coverage and reasons
for exclusions per configuration. For paired comparisons use common successfully
analyzed snapshots; additionally report end-to-end failure/timeout counts and
operational missed-known-site counts so failed cases do not disappear from view.
Final reporting separates language and data source and assesses uncertainty by
independent group when sample size allows. A few groups do not justify precise
population claims.

## 6. Evidence policy v0.1 and controls

- G0: failed/partial evidence extraction, ambiguous association, unsupported
  modeling or conflicting evidence -> inconclusive, plus separate run error.
- S1: a modeled untrusted-source path reaches the relevant command argument at
  the same supported sink -> supported.
- R1: positive evidence accounts for all possible command values/definitions in
  the stated model, resolving to a finite set of literal/concatenated-literal
  commands in a narrowly validated grammar -> proposed_reject for that site.
- U1: remaining cases -> inconclusive.

R1 excludes unresolved branches/aliases, expansion, nested interpreters and called
programs that interpret arguments as code. A literal or no taint path alone is
insufficient. General allowlists, reachability and argument semantics are candidate
additional evidence, not implemented rejection rules. Keep unsupported cases.

Reuse of a CodeQL path for explanation is legitimate but is not an independent
validation or new evidence by itself. Labels remain independent. If custom queries
or models contribute new detections, compare CodeQL with those additions without
the policy. If Semgrep gains a new sink/source model, an equivalent CodeQL model
control is mandatory before claiming superiority attributable to combining tools.
If that control cannot be supplied, restrict the claim and record the limitation.

## 7. Development effort and freeze gates

Initial pilot effort budgets (research design choices, not promised schedules):

| Activity | Budget per language | Maximum revision rounds |
|---|---|---|
| Tune S1 rules | 4 active person-hours | 2 |
| Develop evidence queries/policy | 8 active person-hours | 4 |
| Add equivalent tool source/sink models, if needed | 4 active person-hours per tool | 2 |

Log active minutes, developer, development case IDs, purpose, patch/config commit,
round and outcome. Report common infrastructure separately from method-specific
work. Stop at the first exhausted limit or completion of planned revisions. An
extension requires a dated protocol amendment before opening the check set.
Equivalent coverage controls are still required; budget exhaustion is not permission
to compare custom Semgrep unfairly against unmodeled CodeQL.

Before any pilot-check/final held-out run, commit:

1. This protocol and amendment history.
2. Inventory and group split; K reference set and threat model.
3. Exact CLI/engine/container versions, rule/query/model files and hashes,
   matching version, policy version, timeouts, resources and repetition policy.
4. Development effort log and the frozen configuration manifest.

The present protocol commit precedes development pilot execution. It is not a
complete final preregistration until those artifacts exist. Block held-out runs
when any item is missing. Record protocol_commit, configuration_commit,
labels_commit, dataset_manifest_sha256 and mapping version in every run/report.
A commit is an audit trail of ordering, not proof of absence of prior exposure.

## 8. Ordered pilot decisions and fallback paths

These are feasibility gates, not statistical significance tests:

1. Invalid acquisition/execution/labels/mapping: fix the harness or report an
   incomplete pilot; do not choose a method from invalid comparisons.
2. Any previously detected known true location lost by ST on the pilot check:
   do not accept the current suppression policy. Preserve the failure; revisions
   occur on development data and need fresh independent evaluation.
3. No confirmed FP: no FP-reduction claim; obtain suitable independently reviewed
   cases or report detection/feasibility only.
4. ST removes at least two additional FP units across at least two independent
   groups relative to S1 and loses no additional true locations: continue policy
   research and report incremental runtime/effort. Two units are a pilot gate,
   not evidence of general superiority.
5. Otherwise: no sufficient pilot evidence to prefer the policy to rule tuning.

Separately, at least two Semgrep-only true sites from two independent groups
triggers consideration of a union-input experiment. Absence on this small pilot
is not proof that Semgrep never contributes. Inspect complementary misses even
when CodeQL has better aggregate scores.

If Q0 dominates the combination on measured quality and cost, document the negative
result and discuss scope/acceptability with the supervisor. A CodeQL-only
adjudication layer, framework-specific models or CI scheduling are alternative
research questions needing their own evidence; none is an automatic success path.
CI scheduling needs repeated-revision/time-to-detection evaluation, not one scan.
Scope changes to approved tools/languages require confirmation under applicable
institutional rules; this document does not claim administrative approval.

## 9. Runtime measurement and artifacts

Record fetch, Semgrep, CodeQL database-create, CodeQL analyze, normalization/policy
and total wall-clock separately. Report extra adjudication cost, not presumed
savings. Hold CPU/RAM/timeouts fixed; label cold, warm and cached-result runs.
Functional pilot runs are not runtime benchmarks. Before final evaluation, use
three fresh-workspace sequential repetitions per configuration on the same host;
record host/tool-cache conditions and report median plus range. If parallelizing,
report task times separately from wall-clock and amend the execution plan.

Reuse immutable raw outputs for post-processing but do not report cached latency
as scan time. Retain manifests, hashes, command argv, tool version, exit code,
stdout/stderr, SARIF/raw output, completeness status, mapping, decisions and labels.
Never execute benchmark exploits or untrusted installation hooks as part of source
acquisition. Source fetching and static scanning are distinct from exploit validation.

## 10. Amendment log

| Version | Date | Change | Data exposure at change |
|---|---|---|---|
| 1.0.0 | 2026-09-28 | Initial consolidated protocol: CWE-free identities, fallback ledger, two-axis labels, K/N/G, common-unit metrics, four configurations, budgets and ordered gates | No scanner execution under this protocol; public benchmark metadata inspected |

For each amendment record the previous commit, reason, changed sections, data
already observed and whether a new holdout is required. Never overwrite an earlier
reported result or silently relabel a check set as untouched.
