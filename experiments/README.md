# Experiments

The authoritative design is [EVALUATION_PROTOCOL.md](EVALUATION_PROTOCOL.md).
Protocol v1.0.0 was committed before development scanning at
`80db12b6f7b275501f9c0f260c90cd05e818491e`.

## Available now

`run_pilot.py` is one configuration-driven CLI. The first implementation supports
pinned JavaScript npm tarballs, Semgrep and CodeQL, raw SARIF preservation and a
lossless review ledger/CSV. It rejects non-development cases. It does not yet
implement adjudication, automatic sink matching, S1 tuning or metric computation.
The first configuration is an integration smoke test, not the frozen S0/Q0 suite.
It uses one upstream Semgrep audit rule and two CodeQL command-injection queries;
no custom rules/models have been added.

Archive identity is checked using SHA-256 and registry integrity. Extraction
rejects traversal, links, duplicate paths and excessive sizes/file counts. No npm
install or benchmark exploit is executed. Every failed attempt keeps its report.
Source labels remain separate from the acquisition/scanner manifest.

## Run with Docker

From the repository root (Linux x86-64; Docker host required):

```bash
docker build -f experiments/Dockerfile -t security-triage-pilot .
mkdir -p artifacts
docker run --rm \
  -v "$(pwd)/artifacts:/app/artifacts" \
  security-triage-pilot \
  --case experiments/cases/secbench-curling-0.2.0.json \
  --config experiments/configs/development-smoke-javascript.json \
  --configuration-commit 8ffd191a4b63d74db3b655aeb08c3ce9aa33a4c5 \
  --output artifacts/curling-local-001
```

The output directory must be new. The commit above pins the native runner/config
used for the recorded second attempt. If code/config changes, pass its actual
committed revision and rebuild the image; hashes also appear in run.json.
This dedicated Dockerfile is supplied for convenience; it has not been built in
the authoring environment, which has no Docker daemon. The recorded pilot uses
the same tool versions natively. The web application's earlier Docker CI success
is not evidence for this new experiment image.

The image installs Semgrep 1.178.0 with pinned Python dependency versions and the
checksum-verified JavaScript-only CodeQL 2.27.1 bundle. Python scanner support is
not yet wired into this runner. Use CodeQL in accordance with its license; this
pilot scans an open-source package.

## Native invocation

Use Python 3.12+, Semgrep 1.178.0 and the JavaScript CodeQL bundle 2.27.1. Both CLI
paths and the bundled javascript-queries/2.4.6 directory can be supplied:

```bash
python3 experiments/run_pilot.py \
  --case experiments/cases/secbench-curling-0.2.0.json \
  --config experiments/configs/development-smoke-javascript.json \
  --configuration-commit 8ffd191a4b63d74db3b655aeb08c3ce9aa33a4c5 \
  --semgrep /path/to/semgrep \
  --codeql /path/to/codeql/codeql \
  --javascript-query-pack /path/to/codeql/qlpacks/codeql/javascript-queries/2.4.6 \
  --output artifacts/curling-local-001
```

Outputs: source archive, extracted source, pinned case/config, fetched rules,
version/process logs, SARIF, findings.json, findings.csv, run.json and CodeQL DB.
Raw output is distinct from a reviewed location/label ledger. Do not interpret raw
finding count as unique vulnerabilities or calculate F1 before mapping and labeling.
Artifacts/ is ignored by Git; compact evidence and report extracts live in reports/.

Run focused offline checks with:

```bash
python3 -m unittest experiments.test_runner -v
```

## Recorded development run

See [curling 0.2.0 pilot report](reports/curling-0.2.0/REPORT.md): both tools ran,
Semgrep returned zero raw findings and CodeQL six. A subsequent
[source review](reports/curling-0.2.0/SOURCE_REVIEW.md) maps the six alerts to one
in-scope CWE-78 TP location, with an unblinded assistant first review and independent
human review pending. This remains a development checkpoint, not an accuracy comparison.

## Sink proposal and review packet

An offline review builder now verifies the preserved evidence and proposes sink
aliases for the pinned CodeQL shell-command-construction result format. It keeps
all fallback records and leaves mapping decisions and truth labels unresolved.
See [REVIEW_WORKFLOW.md](REVIEW_WORKFLOW.md) for commands, limitations and manual
review fields. Six runner tests plus six review tests pass locally (12 total).
Application test counts are tracked separately; see the latest batch report.

## Development rule diagnostic

The shared CLI now accepts checksum-pinned repository rules and an optional
`--source-archive` cache with manifest verification. On the same curling archive,
the upstream smoke rule returns 0 raw findings and a direct-alias extension returns
1 at line 56. This is an S1 development candidate, not the frozen tuned baseline;
the shared location now has a [first-review TP label](reports/curling-0.2.0/SOURCE_REVIEW.md),
while frozen cross-configuration scoring and effectiveness metrics remain pending. See the
[paired diagnostic report](reports/curling-direct-alias/REPORT.md). There are now
14 offline experiment tests, separate from application backend tests.

## Five-package development survey

See [batch 01 report](reports/development-batch-01/REPORT.md) for six raw Semgrep
alerts and zero CodeQL alerts across five completed paired snapshots. The report
preserves failed attempts and preliminary capped review; no FP or accuracy gain
is confirmed. Run further fixed batches with `python -m experiments.run_batch`.

## Application-helper development survey

[Batch 02](reports/development-batch-02/REPORT.md) records four Semgrep and one
CodeQL alert across three published snapshots. The node-notifier sanitizer
review is a concrete hypothesis awaiting validation, not a confirmed FP.

## NotifySend path diagnostic

[Follow-up review](reports/development-batch-02/PATH_REVIEW.md) records four CodeQL
traces and bounded argument-construction checks. The shared sink stays unresolved;
no accuracy metric or exclusion rule is enabled.

## R1 candidate feasibility

[Ten synthetic probes](reports/r1-feasibility/REPORT.md) check whether the current
upstream rules leave constant-command candidates for R1. Semgrep emits six alerts
and CodeQL three; an explicit interpreter probe is Semgrep-only. This is mechanism
evidence, not real-data FP reduction or recall improvement.

## Rule meaning and CWE annotation

`python -m experiments.annotate_claims` annotates recorded scans without removing
findings. The [versioned mapping](mappings/README.md) separates API-use warnings
from modeled flows and preserves unknown classifications. [Results](reports/rule-claims-v1/REPORT.md)
retain all 11 alerts from the eight real packages and all nine synthetic alerts.

## Platform scope and complete preliminary coverage

[Follow-up review](reports/development-batch-02/SCOPE_REVIEW.md) records the
Windows-only launch-editor sink as out of the Linux/POSIX threat model, with its
technical verdict still unresolved. This is not an FP or a policy suppression.
The previously capped gulp-shell options alert now has source notes: all 11 batch
alerts have preliminary review, but confirmed in-scope FPs remain zero. R1 still
has no defensible negative example; no suppressor or effectiveness metric is enabled.
