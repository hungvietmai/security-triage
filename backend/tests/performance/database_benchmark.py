"""Manual PostgreSQL page benchmark in an isolated schema, with synthetic evidence only."""

import gc
import json
import os
import statistics
import time
import tracemalloc
import uuid

from sqlalchemy import create_engine, event, insert, text
from sqlalchemy.orm import Session

from app import models  # noqa: F401 (registers every table)
from app.core.database import Base
from app.core.pagination import PageParams
from app.features.findings.models import Finding
from app.features.projects.models import Project
from app.features.scans.models import Scan, ToolRun
from app.features.sources.models import SourceSnapshot
from app.features.triage.models import LocationUnit, UnitAssessment, UnitFinding
from app.workflows.scans.schemas import Tool
from app.workflows.scans.service import list_units


def main():
    url = os.environ["TEST_DATABASE_URL"]
    engine = create_engine(url)
    schema = "perf_" + uuid.uuid4().hex
    count = 5000
    project_id, snapshot_id, scan_id, run_id = [uuid.uuid4() for _ in range(4)]
    with engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    scoped = engine.execution_options(schema_translate_map={None: schema})
    queries = []

    def record(conn, cursor, statement, parameters, context, executemany):
        queries.append(statement)

    try:
        Base.metadata.create_all(scoped)
        with scoped.begin() as connection:
            connection.execute(insert(Project), [{"id": project_id, "name": "Performance fixture"}])
            connection.execute(
                insert(SourceSnapshot),
                [
                    {
                        "id": snapshot_id,
                        "project_id": project_id,
                        "bucket": "unused",
                        "object_key": "unused",
                        "status": "ready",
                    }
                ],
            )
            connection.execute(
                insert(Scan),
                [
                    {
                        "id": scan_id,
                        "snapshot_id": snapshot_id,
                        "status": "completed",
                        "reconciler_version": "v1",
                        "policy_version": "p1",
                    }
                ],
            )
            connection.execute(
                insert(ToolRun),
                [
                    {
                        "id": run_id,
                        "scan_id": scan_id,
                        "tool": "semgrep",
                        "language": "python",
                        "status": "completed",
                    }
                ],
            )
            unit_ids = [uuid.uuid4() for _ in range(count)]
            finding_ids = [uuid.uuid4() for _ in range(count)]
            connection.execute(
                insert(LocationUnit),
                [
                    {
                        "id": uid,
                        "scan_id": scan_id,
                        "unit_key": f"{i:06d}",
                        "path": f"app/{i}.py",
                        "mapping_status": "mapped",
                        "reconciler_version": "v1",
                        "locator_version": "l1",
                        "argument_role": "shell_command",
                        "sink_kind": "os.system",
                    }
                    for i, uid in enumerate(unit_ids)
                ],
            )
            connection.execute(
                insert(UnitAssessment),
                [
                    {
                        "unit_id": uid,
                        "priority": "P1",
                        "decision_id": "D01",
                        "reason": "benchmark",
                        "policy_id": "p",
                        "policy_version": "p1",
                        "policy_sha256": "a" * 64,
                        "spec_sha256": "b" * 64,
                        "rule_claims_version": "c",
                        "rule_claims_sha256": "d" * 64,
                        "evidence": {"tools": ["semgrep"], "raw": "x" * 32768},
                    }
                    for uid in unit_ids
                ],
            )
            connection.execute(
                insert(Finding),
                [
                    {
                        "id": fid,
                        "tool_run_id": run_id,
                        "result_index": i,
                        "rule_id": "r",
                        "file_path": f"app/{i}.py",
                        "message": "benchmark",
                    }
                    for i, fid in enumerate(finding_ids)
                ],
            )
            connection.execute(
                insert(UnitFinding),
                [
                    {"unit_id": uid, "finding_id": fid, "reconciler_version": "v1"}
                    for uid, fid in zip(unit_ids, finding_ids, strict=True)
                ],
            )
        with scoped.begin() as connection:
            for table in Base.metadata.sorted_tables:
                connection.execute(text(f'ANALYZE "{schema}"."{table.name}"'))
        event.listen(scoped, "before_cursor_execute", record)
        results = []
        cases: list[tuple[Tool | None, int]] = [(None, 0), ("semgrep", 0), (None, 4000)]
        for tool, offset in cases:
            times = []
            query_counts = []
            for i in range(12):
                with Session(scoped) as session:
                    scan = session.get_one(Scan, scan_id)
                    queries.clear()
                    start = time.perf_counter()
                    page = list_units(
                        session,
                        scan,
                        page=PageParams(limit=20, offset=offset),
                        tier=None,
                        tool=tool,
                    )
                    assert len(page.items) == 20 and page.total == count
                    elapsed = (time.perf_counter() - start) * 1000
                    if i >= 3:
                        times.append(elapsed)
                        query_counts.append(len(queries))
            with Session(scoped) as session:
                scan = session.get_one(Scan, scan_id)
                gc.collect()
                tracemalloc.start()
                page = list_units(
                    session, scan, page=PageParams(limit=20, offset=offset), tier=None, tool=tool
                )
                _, peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()
            results.append(
                {
                    "units": count,
                    "evidence_bytes_per_unit": 32768,
                    "limit": 20,
                    "offset": offset,
                    "tool": tool,
                    "median_ms": round(statistics.median(times), 3),
                    "select_count": max(query_counts),
                    "peak_python_kib": round(peak / 1024, 1),
                }
            )
        print(json.dumps(results, indent=2))
    finally:
        try:
            with engine.begin() as connection:
                connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        finally:
            engine.dispose()


if __name__ == "__main__":
    main()
