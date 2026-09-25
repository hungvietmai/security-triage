# Architecture and scope

This repository is the initial development foundation, not a working vulnerability scanner.

## Implemented

- React/TypeScript project creation and paginated project list; honest loading/error/empty states.
- FastAPI project creation/list/detail endpoints, liveness and dependency readiness.
- SQLAlchemy foundation: projects → source_snapshots → scans → tool_runs → findings.
- Immutable Alembic migration file, UUID keys, foreign keys, uniqueness and status constraints.
- Redis/Celery worker and diagnostic ping task; S3 client and idempotent bucket initializer.
- Docker runtime builds, development override, persistent database/broker/object-store volumes.
- Tests and CI configuration. Readiness checks PostgreSQL/schema, Redis and S3;
  worker availability is a separate Docker healthcheck.

## Next milestones

1. A manifest-driven Python runner fetches one real SecBench.js case at a fixed
   package version/artifact hash or Git commit and runs Semgrep, preserving raw
   output, configuration, timing and failures. Reuse its adapters from Celery later.
2. Persist immutable snapshots and add structured provenance through a new
   migration. Run CodeQL on the same source; measure database creation and query
   analysis separately. In parallel, label at least two real cases independently
   using advisory/patch/source evidence.
3. Pilot CWE-78 evidence rules on JavaScript and Python, supported by small
   branch-specific fixtures. Inventory eligible cases and record acquisition,
   labeling and analysis failures. Target five cases per language for feasibility,
   not as a sufficient final sample size.
4. Freeze scope, configurations, policy, grouped development/held-out split and
   acceptable recall-loss threshold before the final evaluation.
5. Complete the scan API, worker lifecycle and evidence UI; add folder selection,
   filter preview, automatic ZIP packaging and bounded upload for the demo.

The primary research pipeline only adjudicates Semgrep candidates. CodeQL-only
findings are retained for an independent baseline and missed-vulnerability
analysis; they are not added to the primary pipeline output. With identical
inputs and evaluation mapping, pipeline recall cannot exceed screening recall.
The objective is higher precision with measured, bounded recall loss.

Initial policy v0.1 is a design, not implemented behavior:

- G0: incomplete/failed analysis, unsupported modeling, ambiguous sink matching
  or conflicting evidence yields `inconclusive`.
- S1: a modeled untrusted source-to-command path at the same sink and argument
  yields `supported`.
- R1: complete positive evidence that every possible command value is a resolved
  literal/concatenation in a narrowly validated command grammar yields
  `proposed_reject` for that specific CWE-78 sink. Exclude shell expansion,
  nested interpreters and unresolved definitions; record trusted-environment
  assumptions. A missing taint path or a `const` declaration is insufficient.
- U1: remaining candidates yield `inconclusive`.

Begin with direct shell invocation on Linux/POSIX: Node.js exec/execSync,
Python os.system and subprocess run/Popen with shell=True. Check exported API
input models for package cases; HTTP-only sources may miss these entry points.
Match snapshot, file, sink AST location, command argument and weakness family.

The primary policy retains `supported` and `inconclusive`. A sensitivity analysis
retains only `supported`, reporting both FP reduction and lost true positives.
Pipeline inconclusive states and unresolved independent labels are distinct.
Measure added adjudication cost first. Query selection is an optional optimization
experiment; do not claim savings from filtering already-computed output.

Evaluation initially targets JavaScript and Python. TypeScript evaluation needs
actual independent TypeScript cases and remains conditional on data availability.

Both fetched and uploaded archives need size/count limits, traversal and symlink
validation before extraction. Preserve relevant configuration and lockfiles.
Do not execute source or automatically install dependencies. The API must not run
long scans inline. Folder upload is a demo input; versioned manifests are the
primary experimental input.

## Storage

- PostgreSQL: metadata, normalized findings, status and provenance.
- SeaweedFS: source ZIPs, manifests, raw SARIF, logs.
- Worker-local scratch: extraction and CodeQL databases, disposable after retention policy.
- Git: application code, rules, migration history, manifests and small curated test fixtures.

## Planned provenance changes

The existing source_snapshots table stores artifact metadata but lacks structured
origin fields. Add source_kind, repository_url, resolved_commit, ecosystem,
package_name, package_version, artifact_url, source_subdirectory, manifest_sha256
and provenance_verified_at with per-source validation and a fetching state.
Keep the stored-archive sha256 distinct from upstream checksums or any normalized
source-tree hash. Preserve the complete acquisition manifest with each snapshot.
These changes are planned; the current database still has its foundation schema.

Research labels are versioned separately and joined by case_id; scanner input must
not receive ground-truth vulnerability locations. Keep vulnerable/patched versions
in the same evaluation group. Upload metadata supplied by users is not verified
Git provenance.

## Deployment boundary

This is a single-user, localhost-only development setup without authentication. Ports bind
to 127.0.0.1. Before any shared deployment, implement authentication/ownership checks,
TLS, secret management, quotas and isolated scanner workers. Docker for the application
does not itself make arbitrary uploaded source safe to execute.

There is no scan POST endpoint yet, no synthetic scanner output, and no pre-labelled claim
that a missing CodeQL result proves a Semgrep finding false. The five schema tables prepare
for the next milestones; only project endpoints are exposed in this initial version.
