# Amendment 02 — Application-centered triage and vulnerability-pair evaluation

- Date: 2026-10-05; status: **adopted for development; supervisor agreement pending**.
- Base protocol: v1.0.0, commit `80db12b6f7b275501f9c0f260c90cd05e818491e`.
- Previous amendment: [Amendment 01](AMENDMENT_01_QT.md).
- Last published repository state considered before this amendment:
  `62e4b1eddecc47e48d9d29f9161b30e66568c084`.
- This amendment supersedes Amendment 01 where it defines QT as the primary
  method, defines the primary research questions, or pauses application
  integration. QT and Q1 remain preserved as secondary experimental controls.
- Definitions for source provenance, canonical evaluation units, mapping,
  technical/scope labels, failure handling and artifact preservation continue
  to follow the base protocol unless explicitly changed below.
- No new vulnerable/patched pair may be scanned for the study until this
  amendment, the pair inventory schema and the split procedure have been
  committed. This amendment is not retrospective preregistration of any data
  or scanner output already observed.

## 1. Reason and prior exposure

The original sequential design assumed that Semgrep screening followed by
CodeQL-based adjudication could reduce false positives while preserving useful
detections. Development evidence does not currently support making that claim
the central dependency of the project.

Before this amendment, the project had already exposed scanner output and source
labels for curling, eleven npm packages and all twenty CWE-78 OWASP Python
locations. Amendment 01 records provisional OWASP results in which CodeQL Q0
substantially outperformed the selected Semgrep S0 configuration and a
suppression-only method could not recover true locations missed by its upstream
candidate generator. Development package surveys also failed to produce a
sufficient set of confirmed in-scope false-positive units to support a
false-positive-reduction thesis as the primary contribution.

The repository already contains reusable infrastructure that is broader than
that hypothesis: pinned source acquisition, Semgrep and CodeQL execution, SARIF
preservation, finding normalization, canonical location concepts, provenance,
rule-claim annotation, review artifacts, FastAPI, PostgreSQL, Celery/Redis and
a frontend application. The research direction is therefore changed without
discarding this platform.

Manual dataset inspection performed before this amendment identified candidate
command-injection material in PyVul and SecBench.js. The preliminary counts are
approximately 36 PyVul commits across CWE-78/CWE-77/CWE-88 and 47 SecBench.js
command-injection cases with an identifiable fix. These are **candidate inventory
counts only**. They are not the final sample size and may contain duplicates,
related vulnerability families, unsuitable threat models, unavailable source
states or cases that cannot be mapped reliably.

The revised project makes the executable triage tool the primary applied
deliverable. Vulnerable/fixed pairs are used to develop and evaluate the
solution, not as required runtime inputs for ordinary source-code scanning.

## 2. Scope and system modes

### 2.1. Two-level scope

The system has two distinct scope levels.

**General integration scope.** The platform may execute configured Semgrep and
CodeQL rule/query packs, preserve and normalize their SARIF output, reconcile
locations, store provenance and display findings for multiple supported
vulnerability categories.

Support at this level does **not** imply that the proposed evidence model,
priority policy or security claims have been validated for every category.

**Deep validation scope.** The proposed evidence extraction, triage policy,
root-cause analysis and rule/query improvement are designed and evaluated
primarily for command injection.

The primary vulnerability class remains CWE-78. CWE-77 and CWE-88 are retained
as adjacent strata and must be reported separately unless a future amendment,
written before examining held-out outcomes, explicitly changes the primary
scope. They must not be silently pooled into CWE-78 merely to increase sample
size.

The primary languages remain Python and JavaScript. The existing Linux/POSIX
threat model remains in force unless separately amended.

Other taint-style vulnerability families may be used to demonstrate generic
ingestion, execution throughput and interface behavior. Their results must not
be pooled into the primary command-injection accuracy or deep-triage claims
without separate ground truth and validation.

### 2.2. CWE provenance and conflict resolution

Each vulnerability pair must preserve both the source-provided vulnerability
category and the adjudicated CWE used for experimental stratification.

For PyVul, retain the CWE annotation supplied by the dataset together with its
dataset record identifier and provenance.

For SecBench.js, the dataset category `command-injection` is not by itself
sufficient to assign CWE-78, CWE-77 or CWE-88. Retrieve the vulnerability's CWE
from independent advisory sources where available.

Use the following source precedence for experimental stratification:

1. GitHub Security Advisory record when it contains an explicit CWE assignment;
2. NVD record when an explicit CWE is available and the GHSA record does not
   provide one;
3. another maintainer/vendor advisory with an explicit CWE only when neither
   source above supplies a usable assignment;
4. otherwise retain the pair as `cwe_unresolved`.

If authoritative sources disagree, preserve every reported assignment and mark
the adjudicated CWE as unresolved until manually reviewed. Do not select the CWE
that produces the most convenient experimental stratum.

A `cwe_unresolved` pair may remain in inventory and operational demonstrations
but cannot be counted as a primary CWE-78 evaluation group until resolved.

### 2.3. Mode A — scan and triage

Mode A operates on a repository, pinned source snapshot or uploaded source
archive. It does not require a CVE, advisory or security patch.

The target pipeline is:

```text
source
  -> Semgrep + CodeQL
  -> SARIF normalization
  -> canonical location reconciliation
  -> rule-claim annotation
  -> evidence extraction
  -> priority assignment
  -> database/API
  -> findings interface and export
```

For each reconciled candidate location, the system should preserve, where
available:

- original tool and rule/query provenance;
- reported CWE and rule-claim class;
- whether Semgrep, CodeQL or both reported the canonical location;
- source and sink evidence;
- argument role;
- shell/interpreter semantics;
- source-to-sink path evidence;
- guards or sanitizers detected by the implemented evidence extractors;
- evidence completeness and mapping confidence;
- assigned priority tier and explicit reason.

Mode A is the primary application deliverable.

### 2.4. Mode B — evaluation and regression

Mode B accepts versioned vulnerability-pair manifests and invokes Mode A on the
relevant source states.

Its purposes are:

1. evaluate detection on independently known vulnerable locations;
2. compare Semgrep, CodeQL, simple union and the proposed method;
3. study disagreement and false-negative mechanisms on development data;
4. evaluate frozen rule/query improvements on unseen groups;
5. compare ranking policies under fixed candidate sets;
6. detect regression when a rule/query revision gains or loses previously
   detected vulnerable locations.

A vulnerable/fixed pair is therefore an **evaluation and development artifact**,
not a prerequisite for Mode A.

A fixed version is not automatically a negative example. A finding that persists
after a security patch is not automatically a false positive. Cross-version
behavior must be interpreted using the pair mapping and review rules defined
below.

For the **development set**, fixed snapshots may be used to understand remediation
mechanisms, construct counterexamples, refine rule/query logic and validate
regression behavior.

For the **held-out set**, the primary RQ1/RQ3/RQ4 results are based on the
vulnerable snapshots. Fixed snapshots do not determine the primary detection or
ranking claims. They may be scanned after the primary held-out outputs have been
frozen for secondary descriptive analysis and regression checks. If schedule or
resource constraints require it, held-out fixed-version scans may be omitted
without invalidating the primary evaluation.

## 3. Research questions, design objective and configurations

### 3.1. Research questions

**RQ1 — Detection and disagreement.**

What detection, agreement, disagreement and miss patterns occur when Semgrep and
CodeQL analyze independently known command-injection vulnerabilities?

Report at minimum:

- detected by both;
- Semgrep only;
- CodeQL only;
- missed by both.

Counts must be reported at independent vulnerability-group level as well as at
canonical location level where appropriate.

**RQ2 is retired as a research question.**

Building an integrated triage mechanism is a project design objective rather
than a yes/no research question.

**Design objective D1.**

Build an executable system that combines Semgrep and CodeQL output, reconciles
candidate locations, preserves evidence and provenance, classifies rule claims
and produces an explainable review priority for source code not known in advance
to be vulnerable.

**RQ3 — Guided improvement.**

Do rule/query or evidence improvements developed from recurring failure and
disagreement mechanisms detect additional independently known command-injection
locations on held-out groups without losing previously detected known locations?

For small held-out sets, results must primarily be reported as exact counts, for
example “3 additional locations detected out of 28, 0 previously detected
locations lost”, rather than relying on percentage-only presentation.

**RQ4 — Review workload.**

Does the proposed priority policy retrieve independently known vulnerable
locations with less review effort than simple ranking baselines using the same
candidate set?

The primary comparison is against naive rankings, especially a
**CodeQL-first** baseline. A useful ranking claim requires improvement beyond
the advantage obtained merely by placing all CodeQL findings before
Semgrep-only findings.

### 3.2. Detection configurations

| ID | Role | Definition |
|---|---|---|
| S0 | Semgrep baseline | Frozen original command-injection rules |
| Q0 | CodeQL baseline | Frozen original command-injection queries/models |
| U0 | Simple union baseline | Reconciled union of S0 and Q0, without ranking-specific suppression |
| S1 | Semgrep improvement | Development-derived rule/model changes within the declared budget |
| Q1 | CodeQL improvement | Development-derived query/model changes within the declared budget |
| U1 | Improved union | Reconciled union using the frozen available S1/Q1 improvements |
| QT | Secondary control | Amendment-01 evidence adjudication; no longer the primary thesis method |

S1 or Q1 may be unavailable if development evidence does not justify a defensible
improvement. An unavailable configuration receives no fabricated score.

### 3.3. Development-effort budgets

Existing development-effort limits remain applicable and are made explicit here.

| Activity | Budget per language | Maximum revision rounds |
|---|---:|---:|
| S1 Semgrep rule tuning | 4 active person-hours | 2 |
| Evidence extraction and priority-policy development | 8 active person-hours | 4 |
| Q1 direct-query/model integration introduced by Amendment 01 | 4 active person-hours | 2 |
| Equivalent source/sink model additions, if required for fair comparison | 4 active person-hours per tool | 2 |

Active effort must be logged separately from scanner runtime and common
infrastructure work.

Historical development work whose active duration was not measured remains
`unknown`; it must not be reported as zero.

An extension beyond a declared budget requires a dated amendment written before
examining further held-out data.

### 3.4. Triage configurations

**T0** applies the proposed priority policy to the fixed U0 candidate set.

**T1** is the final proposed end-to-end configuration: U1 candidates, when valid
improvements exist, followed by the frozen priority policy. If only one scanner
has a justified improvement, U1 combines that improved scanner with the other
scanner's frozen baseline.

Detection improvement and ranking improvement must be reported separately.
T0 versus naive U0 rankings isolates ranking value. U0 versus U1 isolates
candidate-generation changes.

The priority mechanism in this amendment does not automatically delete findings.
Any future suppression policy must remain separately identifiable, with QT
retained as the existing secondary control.

## 4. Priority policy v0 and naive ranking baselines

### 4.1. Priority policy v0

Priority tiers are intended to be explainable decision categories rather than
an arbitrary weighted score.

| Tier | Development definition |
|---|---|
| P1 — very high review priority | Execution candidate with strong source-to-sink evidence and no automatically verified blocking condition, plus either cross-tool agreement at the same canonical unit or command/shell/interpreter semantics that independently strengthen the security claim |
| P2 — high review priority | A flow-supported command-execution candidate where one important property remains unresolved, or cross-tool agreement exists but one claim is primarily audit-oriented rather than a complete flow claim |
| P3 — manual review required | A single-tool conditional-flow or audit candidate at a relevant execution sink with incomplete trust-boundary, guard, sanitizer, argument-role or command-semantics evidence |
| P4 — audit candidate | Primarily an API-use or broad dangerous-operation warning without demonstrated untrusted flow or equivalent strong evidence |
| U — unresolved | Mapping or evidence extraction is incomplete, contradictory or unavailable |

Human-assigned in-scope/out-of-scope ground truth must not be used as a runtime
feature.

If the runtime system uses an automatically extracted scope condition, that
extractor must be separately versioned, frozen before held-out evaluation and
applied identically to development and held-out data.

`U` is not evidence of safety. For the operational review queue in v0, unresolved
candidates are placed after P2 and before P3 so that extraction failure cannot
silently defer them behind broad audit warnings. They remain visibly labeled U.

The exact decision table, evidence extractors and rule-claim mapping must be
versioned. Changes based on development data require a new policy version.
Held-out results may not be used to revise the version being evaluated.

### 4.2. Evidence asymmetry

CodeQL and Semgrep do not necessarily expose equivalent evidence.

CodeQL queries may provide explicit source-to-sink paths. Semgrep evidence
availability depends on rule type and configuration; taint-mode rules may expose
data-flow traces when the corresponding trace output is enabled, while audit-style
rules may contain substantially less path information.

The system must preserve the strongest evidence each tool actually provides and
must not fabricate symmetric evidence fields.

The priority policy must record when evidence is unavailable because of tool
capability or configuration rather than treating absence of a trace as evidence
of safety.

This asymmetry may naturally favor CodeQL in an evidence-based ranking policy.
For that reason, the required CodeQL-first baseline below is a central control
rather than an optional comparison.

### 4.3. Ranking baselines

Every ranking method receives the **same reconciled candidate set** for the
comparison in question.

**B-RND — random union.**

All candidate units are uniformly randomly ordered within each project. Evaluation
uses the exact expected value under a uniform random ordering rather than a
single favorable random seed.

**B-QF — CodeQL first.**

Every canonical unit containing a CodeQL finding is ranked ahead of units
reported only by Semgrep. Units within each group are treated as tied and their
expected ranking metric is calculated under uniform random ordering.

This is a required baseline.

**B-AGR — agreement first.**

Units reported by both Semgrep and CodeQL are ranked ahead of single-tool units.
Ties within a group are handled uniformly at random in the evaluation.

**B-SEV — native severity.**

Candidates are ranked using normalized original severity only. SARIF severity is
ordered `error > warning > note > none/unknown`. If multiple raw findings map to
one canonical unit, the highest preserved level is used. This is intentionally
a naive baseline; severity scales from different tools are not assumed to be
calibrated.

**T0/T1 — proposed policy.**

Candidates are ordered by the frozen P1/P2/U/P3/P4 policy. Candidates tied in the
same tier are evaluated using their expected position under uniform random
ordering within that tier.

A deterministic canonical-ID order may be used by the web interface to provide
stable display, but that display tie-break must not be used to obtain a more
favorable research result.

## 5. Ranking evaluation, ties and incomplete labels

### 5.1. Ranking scope

Ranking is evaluated **within each project/snapshot**, not by constructing one
global queue across unrelated projects. This reflects the intended workflow in
which a reviewer examines findings for a particular codebase.

Project-level results are then aggregated across independent vulnerability
groups.

### 5.2. Candidate universe

For a U0 ranking comparison, every ranking baseline and T0 receives the same
reconciled U0 candidates from successful scanner runs.

For a U1/T1 ranking comparison, methods being compared must receive the same U1
candidate set unless the purpose of the comparison is explicitly end-to-end
detection.

Manual knowledge that a candidate is a false positive, out of scope or unrelated
to the known vulnerability must not be used to remove that candidate from the
ranking universe.

A separate **Q0-alone end-to-end baseline** is required. Q0-alone contains only
the candidates produced by the frozen original CodeQL configuration. Within Q0,
candidate order is treated as tied and evaluated under uniform random ordering
unless an explicitly declared CodeQL-native ranking baseline is added before
held-out evaluation.

Q0-alone is compared with T1 using the same independent known-vulnerability
denominator, including vulnerable locations missed by Q0, T1 or both.

This comparison answers the operational question of whether the complete proposed
system provides value beyond using CodeQL alone, rather than only showing value
within a preconstructed union candidate set.

### 5.3. Known-vulnerability ranking metrics

Because pair datasets provide strong labels primarily for independently known
vulnerability locations, ranking metrics are explicitly named
**known-vulnerability retrieval metrics** rather than precision estimates.

Report:

1. **Known-vulnerability Recall@K**, for predeclared review depths, calculated
   by reviewing the top `min(K, number_of_candidates)` units in each project.
2. **Conditional Recall@K**, whose denominator contains only known vulnerable
   locations that are present in the candidate set being ranked. This isolates
   ranking performance from detector recall.
3. **End-to-end Recall@K**, whose denominator also includes independently known
   vulnerable locations missed by every candidate generator in the compared
   configuration. This measures the combined detector-plus-ranking system.
4. **Review fraction for 90% known-vulnerability recall**, computed by reviewing
   the same fraction of each project's ranked candidate list and finding the
   smallest observed review fraction that retrieves at least 90% of the relevant
   known vulnerable locations.
5. **Expected known-vulnerability rank**, defined as the expected rank of each
   independently known vulnerable location after accounting for ties under the
   declared uniform-within-tier rule.

For expected known-vulnerability rank, report the distribution across held-out
groups using exact group counts together with median and range or interquartile
range when sample size permits.

A group with several independently known vulnerable locations contributes one
rank observation per known location; those observations must remain associated
with their common group identifier and must not be misrepresented as independent
projects.

The exact K values must be declared before the held-out run after the development
candidate-count distribution is known. They may not be chosen after inspecting
held-out ranking results.

### 5.4. Tie handling

No research result may depend on alphabetical file order, database insertion
order, tool execution order or another accidental ordering inside a priority
tier.

For B-RND and every tied group in B-QF, B-AGR, B-SEV, Q0-alone and T0/T1, primary
ranking metrics use the expected result under uniform random ordering within the
tied group.

The implementation may additionally report best/worst tie bounds as sensitivity
information, but those bounds must not replace the expected value as the primary
comparison.

### 5.5. Unlabeled findings

A scanner finding outside the independently known vulnerability location is not
automatically a false positive. Such findings remain candidates and count toward
review workload unless independently reviewed.

Therefore:

- unlabeled findings count as items a reviewer would have to inspect;
- they do not contribute to a false-positive denominator merely because no
  advisory mentions them;
- full-corpus precision/F1 must not be reported unless the relevant candidate
  universe has been independently resolved under the review protocol;
- report the number and proportion of unresolved/unlabeled candidate units for
  every ranking experiment.

Known-vulnerability retrieval may conservatively understate true security yield
if some unlabeled findings are additional real vulnerabilities. It must not be
described as a complete real-world precision measurement.

## 6. Vulnerability pairs, cross-version mapping and data splits

### 6.1. Pair identity

Snapshot-level canonical identities remain unchanged.

Do not force vulnerable and fixed locations into the same canonical source-unit
identifier. Add a separate pair-level identity containing at minimum:

```text
pair_id
repository
vulnerability_id
language
dataset_reported_category
reported_cwes
adjudicated_cwe
cwe_provenance
vulnerable_ref
fix_commit
fixed_ref
reference_provenance
split
```

Cross-version relations may include:

```text
modified_to
moved_to
removed_by_patch
replaced_by_safe_construct
unresolved_cross_version
```

A sink disappearing after a patch is not by itself proof of semantic remediation.

### 6.2. Patch-associated interpretation

A pre-patch finding may be considered patch-associated only when:

1. it maps to an independently supported vulnerable location;
2. the fix commit/version has documented security provenance;
3. the relevant source change is in a changed hunk or has a reviewed direct
   data/control relationship to the changed hunk;
4. the scanner-output difference is not explained by failed analysis, changed
   file coverage or acquisition error; and
5. the vulnerable-to-fixed relation has been recorded.

File deletion, rename, movement or unrelated refactoring must not be silently
interpreted as successful vulnerability remediation.

### 6.3. Grouping

Repository/vulnerability families, duplicate benchmark records, forks, near
duplicates and repeated affected versions must remain in the same group.

The statistical or descriptive unit for primary held-out claims is the
independent vulnerability group, not every affected package version or commit.

### 6.4. Prior exposure

Any group whose source, labels or scanner outcome has already materially
influenced rules, queries, evidence logic or project decisions is development
data and may not become final held-out evidence.

Existing curling, npm-development and OWASP observations remain development
evidence.

### 6.5. Split procedure

Before scanning fresh pair candidates:

1. build and commit the candidate inventory;
2. resolve or explicitly mark CWE provenance under Section 2.2;
3. deduplicate candidates into independent repository/vulnerability groups;
4. mark all previously exposed groups as development;
5. stratify remaining eligible groups by language, dataset and primary/adjacent
   CWE stratum where sample size permits;
6. order candidates within each stratum deterministically using a committed hash
   of the group identifier;
7. commit the development, held-out and reserve lists before scanner execution.

At least 40% of otherwise eligible fresh primary-scope groups should remain
held out where the available inventory permits. A minimum of ten fresh held-out
primary groups is preferred before making a general performance claim.

Acquisition or build failures may be replaced only using the next candidate in
the precommitted reserve order. Scanner performance must never determine
replacement.

If fewer than ten independent primary held-out groups complete successfully,
results are reported as a pilot rather than as broad evidence of effectiveness.

If the deduplicated CWE-78 inventory cannot support both the declared development
and held-out requirements, the study must either:

- proceed explicitly as a smaller CWE-78 pilot; or
- adopt a new amendment expanding the primary scope to adjacent CWE classes
  **before** examining held-out scanner outcomes.

CWE-77/CWE-88 must not be pooled post hoc merely to repair an undersized or
unfavorable held-out result.

## 7. Root-cause analysis and improvement development

### 7.1. Role of root-cause analysis

Manual root-cause analysis is a development activity supporting the proposed
tool. It is not the primary standalone product.

It seeks recurring explanations for:

- Semgrep-only known detections;
- CodeQL-only known detections;
- vulnerabilities missed by both;
- evidence-extraction failure;
- disagreement caused by source/sink modeling, aliasing, wrappers,
  interprocedural flow, command construction, argument role, shell/interpreter
  semantics, guards, sanitizers, platform or trust boundary.

The initial taxonomy is versioned and may evolve only on development data.

### 7.2. Root-cause review population

The deep root-cause population is defined **before** manual causal review.

After frozen S0 and Q0 have been run on development groups, a group is eligible
for deep root-cause analysis if at least one independently known vulnerable
location in that group is:

- detected by Semgrep only;
- detected by CodeQL only;
- missed by both tools; or
- affected by unresolved evidence extraction or canonical mapping that prevents
  a valid comparison.

Groups in which all known vulnerable locations are cleanly detected by both
tools are not part of the primary saturation population.

To avoid learning only from failures, a deterministic reference sample of up to
three both-detected development groups is also reviewed. These reference groups
are analyzed separately and do not count toward the five-group taxonomy
saturation stopping rule.

Eligibility is determined mechanically from frozen S0/Q0 outcomes and independent
known-vulnerability mappings. Researchers may not choose individual groups
because they appear especially interesting after reading their source code.

### 7.3. Review order and stopping rule

Eligible development groups are processed in a precommitted deterministic hash
order.

Review at least 15 independent eligible groups if that many are available. If
fewer than 15 eligible groups exist, review all of them and report that the
planned minimum was not available.

After the first 15 eligible groups, stop deep root-cause collection when **five
consecutive independent eligible groups** introduce neither:

- a new root-cause category; nor
- a material change to the definition of an existing category.

Continue no further than 25 deeply reviewed eligible groups for the primary
development cycle. If the saturation rule has not been met by group 25, stop
because of the declared effort bound and report that taxonomy saturation was
not reached.

The stopping rule applies to taxonomy development, not to automated held-out
scanning.

### 7.4. Improvements

A development observation may motivate:

- a Semgrep rule/source/sink refinement;
- a CodeQL query/model/barrier refinement;
- an evidence extractor;
- a priority-policy condition.

Every change must record:

- motivating development groups;
- mechanism being addressed;
- counterexample or negative fixture where applicable;
- versioned implementation diff;
- active development effort;
- expected effect;
- possible failure modes.

A change derived from one case may be implemented for exploration, but no
general benefit is claimed until frozen evaluation on independent held-out
groups.

Once S1, Q1, evidence logic and the priority policy are frozen, held-out
failures do not authorize modification of the evaluated configuration. A held-out
group inspected to change the method becomes contaminated development evidence
and cannot remain in the final held-out score.

## 8. Result reporting, runtime and decision gates

Small command-injection samples must be reported primarily using exact counts and
denominators.

Prefer statements such as:

```text
S1 detected 3 additional known vulnerabilities among 28 held-out groups and
lost 0 locations detected by S0.
```

Do not rely on percentage-only summaries when counts are small.

No null-hypothesis significance test is planned for the primary pilot-scale
comparison. Report project/group counts, candidate counts, exact detection
transitions, ranking curves, expected vulnerable-location ranks and review-effort
metrics.

### 8.1. Runtime and operational cost

Runtime measurement follows the base protocol.

Record separately:

- source acquisition;
- Semgrep execution;
- CodeQL database creation;
- CodeQL analysis;
- normalization and canonical reconciliation;
- evidence extraction and priority assignment;
- persistence/API overhead where measured;
- total wall-clock time.

For final runtime comparison, use the repetition and host/cache controls declared
in the base protocol. Report extra triage cost rather than assuming operational
savings from ranking alone.

### 8.2. Ordered interpretation

Apply the following ordered interpretation:

1. **Incomplete acquisition, scanner failure, unresolved essential mapping or
   invalid split:** affected cases do not become successful negative scans.
   Coverage and failures are reported explicitly.
2. **Too little held-out evidence:** fewer than ten successful independent
   primary held-out groups supports a pilot/feasibility conclusion only.
3. **Detection improvement:** report exact S0→S1 and Q0→Q1 gains and losses.
   Any lost known vulnerable location must be shown explicitly.
4. **Ranking value:** T0 must be compared against B-RND, B-QF, B-AGR and B-SEV
   on the same U0 candidates. A ranking claim must not be based solely on
   outperforming random order.
5. **CodeQL-first control:** if T0 does not materially improve known-vulnerability
   retrieval, expected vulnerable-location rank or review effort over B-QF,
   conclude that the proposed evidence policy has not established added ranking
   value beyond prioritizing CodeQL findings.
6. **CodeQL-alone end-to-end control:** compare Q0-alone against T1 using the same
   independent known-vulnerability denominator. If T1 does not improve detection
   coverage and review effort sufficiently to justify its additional complexity,
   do not claim an end-to-end advantage over CodeQL alone.
7. **Unlabeled candidate burden:** ranking gains must be reported together with
   unresolved/unlabeled counts; do not reinterpret those candidates as false
   positives.
8. **Negative outcomes remain reportable:** failure to improve ranking or
   detection is a valid result but does not authorize post-hoc policy changes on
   held-out data.

Broader taint-style findings may support secondary operational demonstrations,
but must remain separate from the deep command-injection effectiveness tables.

## 9. Implementation sequence and application boundary

The immediate implementation target is a minimal end-to-end vertical slice:

```text
source submission
  -> backend scan job
  -> Semgrep and CodeQL
  -> normalized findings
  -> canonical reconciliation
  -> rule-claim annotation
  -> priority assignment
  -> database
  -> API
  -> findings displayed in the frontend
```

The milestone is complete when one real source snapshot can pass through this
entire path and the reconciled findings with provenance, evidence status and
priority reason are visible through the application.

Frontend work before that milestone is limited to what is required for the
vertical slice. Authentication, multi-user support, visual polish, elaborate
dashboards and unrelated upload features are not research priorities.

Mode B may initially remain a CLI/report workflow. It does not require a dedicated
frontend before the primary evaluation.

After the vertical slice:

1. commit the pair schema and inventory;
2. freeze the development/held-out/reserve split;
3. run the stratified development pilot;
4. perform bounded root-cause analysis;
5. implement and freeze justified S1/Q1/evidence/policy changes;
6. run held-out evaluation once under the frozen configuration;
7. optionally run fixed held-out snapshots for secondary remediation/regression
   description after the primary held-out outputs are frozen;
8. complete the findings interface and final report.

QT/Q1 artifacts from Amendment 01 remain preserved. Q1 may become part of the
improvement study; QT remains a secondary evidence-adjudication control rather
than the thesis's central dependency.

## 10. Administrative and freeze boundary

This amendment changes the primary methodological emphasis from sequential
false-positive suppression to an application-centered triage and evaluation
system. It does not claim that this methodological change is automatically
approved under the existing thesis title or proposal.

The thesis/report should explicitly contain an “Adjustment from the approved
proposal” section describing:

- the development evidence that weakened the original sequential hypothesis;
- the revised application-centered deliverable;
- the two-level scope;
- the distinction between runtime scanning and vulnerable/fixed evaluation;
- the role of Semgrep/CodeQL improvements;
- the retained single-reviewer and ground-truth limitations.

Supervisor/institutional agreement remains an administrative requirement.

Before the first new vulnerability-pair scan, commit and publish:

1. this amendment with status **adopted for development**;
2. pair-manifest schema;
3. candidate inventory with CWE and reference provenance;
4. grouping/deduplication rules;
5. deterministic split and reserve procedure;
6. initial root-cause taxonomy;
7. ranking baseline definitions;
8. priority-policy version used for the development run.

Before the final held-out run, additionally freeze and publish:

- final source/config hashes;
- S0/Q0/S1/Q1 definitions;
- U0/U1 mapping logic;
- rule-claim mapping;
- evidence extractors;
- priority-policy version;
- held-out group list;
- evaluator version;
- review records required by the protocol.

Each methodological freeze should be associated with a published repository
commit and, where feasible, an externally service-recorded milestone such as a
GitHub tag/release or archived CI/workflow artifact. The corresponding URL,
commit SHA and service-recorded publication time should be retained in the
research log.

A local Git author timestamp, an unpushed tag or a manually written date is not
treated as independent evidence of ordering.

This document is **adopted for development** by the commit that introduces it.
No new vulnerability-pair scan is authorized until the remaining pre-scan
artifacts listed above are also committed.
