# Backend performance check

Measured on 2026-10-07. Triage measurements used Python 3.12.10 on the Windows
development host. Database measurements used PostgreSQL 17 and Python 3.12 in
Docker. These are local synthetic benchmarks, not production capacity estimates.

## Findings and changes

- Reconciliation previously normalized and searched every file's sinks for each
  finding. It now indexes sinks by file and source position. Completed finding
  groups are sorted once instead of after every insertion.
- Assessment previously rebuilt all finding/claim lookups for every unit. A
  run-scoped evidence index now reuses those lookups and exact sink identities.
  Duplicate sinks remain ambiguous. Source line indexes are scoped to each run.
- The Python sink locator previously called `ast.get_source_segment` for every
  argument and callee, repeatedly splitting the source. It now indexes physical
  source lines once, preserving UTF-8 byte offsets and CR/LF/form-feed behavior.
- Unit-list queries now select tool names from evidence JSON instead of loading
  the full evidence record. Empty pages skip the assessment query. Detail queries
  still return complete evidence.
- File hashing and artifact uploads now stream files instead of loading each
  complete artifact into memory.

## CPU measurements

Reconciliation plus assessment: medians of three repetitions, excluding fixture
generation, sink location and scanner execution. Each finding references one
simple Python command sink and uses an unresolved rule classification.

| Fixture | Findings | Before | After |
|---|---:|---:|---:|
| One finding per file | 1,000 | 400.8 ms | 55.9 ms |
| Separate calls in one file | 1,000 | 883.6 ms | 57.4 ms |
| Findings sharing one sink | 1,000 | 150.3 ms | 18.2 ms |

Serialized unit and assessment SHA-256 values matched before and after for all
nine compared fixtures: three layouts at 100, 500 and 1,000 findings.

The separate Python sink-location benchmark measured one pass per size:

| Calls in one file | Before | After |
|---|---:|---:|
| 100 | 8.8 ms | 2.2 ms |
| 1,000 | 621.2 ms | 22.6 ms |
| 5,000 | 14,923.6 ms | 117.1 ms |

All three sink-output SHA-256 values matched the previous implementation.
The initial reconciliation/assessment benchmark also processed 5,000 findings
across files or within one file in approximately 311–313 ms.

## Database and memory measurements

The database fixture contains 5,000 units, assessments and finding links, with
32 KiB of synthetic evidence per unit. Tables were analyzed before measurement.
Requests use fresh sessions and 20-item pages. Times are medians of nine measured
repetitions after three warm-up runs; they exclude HTTP, scanners and storage I/O.

| Page | Before | After | SELECTs |
|---|---:|---:|---:|
| First page | 13.2 ms | 12.5 ms | 3 |
| First page filtered by tool | 20.3 ms | 16.8 ms | 3 |
| Offset 4,000 | 13.6 ms | 10.2 ms | 3 |

The main benefit of projecting evidence is memory and transferred data; small
latency differences can vary between runs. Peak Python allocations measured by
`tracemalloc` fell from approximately 807 KiB to 100 KiB for an unfiltered page.
These figures are not process RSS or database-server memory measurements.

Hashing a 32 MiB artifact reduced peak Python allocations from 32,776.5 KiB to
265.4 KiB while preserving its checksum. Artifact upload tests verify file-stream
use and stream closure on both success and failure; no live S3 throughput was measured.

## Caching and parallel execution

Rule classification now uses a bounded, run-local LRU cache for up to 256 distinct
tool/rule identities. Its mapping and verified definitions are fixed for that
invocation. A new invocation builds a new cache; changed definitions, duplicate
definitions and changed mappings are checked again. Profile files and scanner
versions are still verified for every scan.

Classifying 10,000 findings with the same verified rule decreased from 53.9 ms to
8.1 ms (medians of five repetitions), with identical serialized claim hashes.

Worker configuration controls independent parallel work:

| Variable | Default | Range | Effect |
|---|---:|---:|---|
| `SCANNER_WORKERS` | 2 | 1–2 | Semgrep and CodeQL can run concurrently for one language |
| `ARTIFACT_UPLOAD_WORKERS` | 4 | 1–8 | Hash and stream separate output files concurrently |

Languages remain sequential, so one scan runs at most one CodeQL process at a time.
Scanner outcomes and uploaded artifact entries retain configured input order.
Threads never receive database sessions. Active tasks are joined before temporary
workspace cleanup; failed uploads cancel queued work and propagate the original
error after active streams close. Concurrency settings are recorded in scan
provenance and the scanner worker count appears in each language's `run.json`.

The shared scanner adapter defaults to one worker, preserving sequential execution
for experiment CLIs unless callers explicitly request parallel tools. Set both
environment variables to `1` for sequential worker execution.

A controlled upload benchmark with eight files and **simulated 20 ms latency per
upload** measured 166.5 ms with one worker and 43.2 ms with four workers (medians
of three repetitions). Artifact metadata hashes matched. This measures concurrency
overhead and overlap, not live S3 speed or scanner throughput.

## Repeat the checks

From `backend/`, run the manual CPU benchmark:

```powershell
uv run python -m tests.performance.triage_benchmark
uv run python -m tests.performance.parallel_benchmark
```

From the repository root, run the manual PostgreSQL benchmark:

```powershell
docker compose --profile test run --build --rm test python -m tests.performance.database_benchmark
```

The database benchmark uses `TEST_DATABASE_URL`, creates a unique temporary
schema and drops only that schema afterward. Both benchmarks print JSON.
All manual benchmarks run separately from pytest and do not execute uploaded
source or scanners. The parallel benchmark simulates storage delay locally.

Regression tests check comparison counts for disjoint sinks, source-line reuse,
evidence equivalence and ambiguity, query counts, bounded hashing allocations,
and streamed uploads. They use operation/allocation checks rather than timing thresholds.
Barrier-based tests also check concurrent scanner execution, configured result
ordering, upload worker limits, failure propagation and stream cleanup.

## Scope of assurance

The measured paths no longer show the identified quadratic work for these fixtures
or per-item database queries. Highly overlapping sinks can still require more
matching work, and the benchmarks do not cover long CodeQL traces, real scanner
CPU/RAM usage, concurrent workers, live network transfers or frontend rendering.
Larger datasets and concurrent workloads need separate load measurements.
