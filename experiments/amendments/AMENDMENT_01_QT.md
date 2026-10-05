# Amendment 01 — CodeQL candidates and a direct-query control

- Date: 2026-10-05; status: **adopted for development; supervisor agreement pending**.
- Base protocol: v1.0.0, commit `80db12b6f7b275501f9c0f260c90cd05e818491e`.
- Last published evidence at this decision: `e405f02458ff25d9273dbb71e84f9c64ff59a674`.
- This amendment supersedes the primary method, comparisons, review procedure and
  gates in sections 1, 4, 5, 7–8. Other definitions remain in the [protocol](../EVALUATION_PROTOCOL.md).
- This is a response to observed development results, **not preregistration of
  those results**. No untouched test set has been evaluated.

## 1. Reason and prior exposure

Observed: curling, 11 npm packages and all 20 CWE-78 OWASP Python locations,
including source labels and scanner output. OWASP is one synthetic development
group. Provisional Q0 counts are 11 TP / 2 FP / 2 FN (F1 0.8462). S0 has 7 TP /
7 FP / 6 FN; any suppression-only ST has F1 at most 0.70 on this group, even with
perfect false-positive removal. There are no Semgrep-only true locations here.
These observations motivate a pivot; they do not establish general dominance.

Also exposed before this amendment: an unpublished bounded integer-guard query
and its authored fixtures, including OWASP 01097. It proves a branch outcome,
not sink safety. All such work remains development evidence. Existing labels
were written by an unblinded assistant; none has final human review.

## 2. Configurations and hypotheses

| ID | Role | Definition |
|---|---|---|
| Q0 | Primary detection baseline | Original pinned CodeQL queries/models |
| QT | Primary candidate method | Q0 candidates; retain supported/inconclusive, suppress only proposed_reject |
| Q1 | Direct-query control | Q0 plus the same developed evidence conditions expressed inside queries/barriers |
| S0 | Complementarity baseline | Original pinned Semgrep rules |
| U0 | Post-processing control | Reconciled union of S0 and Q0, without policy |

ST and S1 remain secondary development controls; retain their historical records.
The curling one-rule smoke scan and alias diagnostic are not full S0/S1 runs.
Unavailable configurations have no score, rather than an empty prediction set.
QT is a subset of Q0 and cannot improve its recall with fixed mapping. Adding
Semgrep candidates would be a separately named method, not silently QT.

H1: can QT remove Q0 false locations while preserving Q0 true locations?
H2: does QT improve detection quality compared with equivalent Q1 conditions?
H3: what additional true locations does S0 contribute? Report the four-way
partition over independent reference sites as well as candidate counts.

Compare Q0→QT for policy effect, Q0→Q1 for query tuning, QT↔Q1 for incremental
value, and Q0/S0→U0 for complementarity. Identical conditions may give identical
predictions in QT and Q1. Preserved alerts, explanations and abstentions are
separate auditability properties, not an assumed precision/recall advantage.
Q1 also retains original Q0 artifacts and a query diff; it must not be handicapped
by deleting its baseline evidence. Record runtime and development effort separately.

For each QT decision record source, path, argument role, shell/interpreter,
guard/sanitizer, evidence provenance, association confidence, policy version and
reason. Unknown or failed extraction stays explicit. A path already used by Q0
is explanatory evidence; suppression needs an additional verified condition.
Report decision/evidence completeness, inconclusive rate, FP removed and true
locations lost. Do not infer explanation quality merely from nonempty text.

## 3. Data and review

Prioritize vulnerable/patched pairs with exact version/commit, checksum,
advisory and patch references. An advisory informs a boundary; each alert still
needs a scope decision. A patched version is not a negative label. Review residual
alerts for incomplete fixes, unrelated vulnerabilities and actual false claims.

Group by repository/vulnerability family, including versions, forks and near
duplicates. A pair is not automatically an independent group. Commit and push
inventory/splits before scanning new groups; use fresh groups for held-out work.
Already observed packages remain development. Stop random command-wrapper sampling.

The owner performs the human review; software must never fill in their identity
or approval. When no second reviewer is available, retain the single-reviewer
limitation. Prepare a first-pass packet hiding scanner/policy identity and prior
verdicts. Repeat after at least seven days with a fresh order, hiding the first
verdict. Prior exposure to these cases prevents a claim of fully blind review.
Preserve both passes, dates, disagreements and reconciliation; do not overwrite
them. Report per-field self-agreement and counts, not inter-rater reliability.
Compare against independent OWASP expectations/advisory evidence separately;
matching those sources does not constitute a second human review. AI may suggest
counterexamples but is not an independent reviewer. Institutional AI disclosure
requirements must be checked before submission; approval is not assumed here.

## 4. Development budget and ordered decisions

Existing budgets remain: evidence/policy 8 active person-hours and 4 rounds per
language, S1 4 hours/2 rounds, equivalent source/sink models 4 hours/2 rounds per
tool. Add Q1 integration budget 4 hours/2 rounds per language. Share and separately
log evidence research used by QT and Q1; charge only integration to each method.
Record actual active effort, not elapsed tool runtime. Historical unmeasured effort
is unknown, not zero; no equal-effort claim until accounting is complete. Record
an amendment before exceeding a budget, never after inspecting held-out output.

Apply in order on a valid, frozen comparison:

1. Incomplete runs, unresolved essential mapping, missing human review or unequal
   model coverage: exploratory only; repair or report incomplete evaluation.
2. QT loses any Q0 true location: reject the current suppression policy for pilot
   acceptance, retain the counterexample; revise only on development data.
3. Fewer than two confirmed Q0 FP units across two independent groups: report
   mechanism feasibility only, without a general FP-reduction claim.
4. QT removes at least two more FP units than Q1 across two independent groups,
   and loses no additional true locations: provisional quality advantage; report
   cost and all underlying counts. This is not statistical significance.
5. Otherwise: no established quality advantage over Q1. Report ties/tradeoffs and
   auditability separately. An executable method and a negative result are useful
   outputs, not a guarantee that the thesis meets the institution's requirements.

Semgrep-only true sites are assessed separately; absence on development data does
not prove Semgrep never helps. New sources/sinks added for one tool require the
equivalent other-tool coverage control before a superiority claim.

## 5. Execution and administrative boundary

Implement the evaluator against existing data first. Develop E1 guard evidence
plus reaching-definition and command-semantics checks, then E3 route assumptions,
then E4 sanitizer conditions from patches. Each mechanism needs counterexamples.
A constant guard alone cannot suppress an alert. Keep existing conservative R1
exclusions until a versioned extension actually discharges these obligations.

Freeze/push protocol, split, source/config hashes, mapping, labels, policy and
queries before held-out runs. Record the GitHub commit and externally recorded
workflow/publication time where available. Git author timestamps alone cannot
prove prior ordering; Git records also cannot replace supervisor agreement.
No final run is authorized by an amendment without the section 7 freeze artifacts.

The thesis should contain “Điều chỉnh so với đề cương”: pilot basis, QT/Q1 roles,
Bandit/eslint-plugin-security as extensions, single-reviewer limits and observed
outcomes. Whether scope/title changes need approval is for the supervisor and
institution to determine. No claim is made that a name remaining suitable waives
that process. Pause UI work and long reports; use the decision log and executable
artifacts for progress.
