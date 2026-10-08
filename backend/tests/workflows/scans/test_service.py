"""Database conflicts during snapshot creation preserve reuse and retry behavior."""

import uuid
from typing import Any

import pytest
from sqlalchemy import event, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.pagination import PageParams
from app.features.projects.models import Project
from app.features.scans.models import Scan
from app.features.sources.models import SourceSnapshot
from app.features.triage.models import LocationUnit, UnitAssessment
from app.workflows.scans.schemas import ScanCreate
from app.workflows.scans.service import create_scan, list_units


@pytest.fixture
def project(session):
    project = Project(name="Snapshot conflicts")
    session.add(project)
    session.commit()
    return project


def _request() -> ScanCreate:
    return ScanCreate.model_validate(
        {"source": {"kind": "npm", "package": "demo", "version": "1.0.0"}}
    )


@pytest.mark.parametrize("status", ["ready", "failed"])
def test_snapshot_insert_conflict_reuses_and_resets_the_winning_snapshot(
    engine, session, project, status
):
    winner_id = uuid.uuid4()

    def insert_winner(session: Session, context: Any, instances: Any) -> None:
        # Another request commits after our lookup, before our attempted INSERT.
        with Session(engine) as competing:
            competing.add(
                SourceSnapshot(
                    id=winner_id,
                    project_id=project.id,
                    bucket="sources",
                    object_key="snapshots/winner.tgz",
                    source_kind="npm_tarball",
                    source_coordinate="npm:demo@1.0.0",
                    package_name="demo",
                    package_version="1.0.0",
                    status=status,
                    error_message="download failed" if status == "failed" else None,
                )
            )
            competing.commit()

    event.listen(session, "before_flush", insert_winner, once=True)
    scan = create_scan(session, project, _request(), bucket="sources")
    assert scan.snapshot_id == winner_id
    snapshot = session.get_one(SourceSnapshot, winner_id)
    assert snapshot.status == ("validating" if status == "failed" else "ready")
    assert snapshot.error_message is None
    assert session.scalar(select(func.count()).select_from(SourceSnapshot)) == 1
    assert session.scalar(select(func.count()).select_from(Scan)) == 1


def test_unrelated_snapshot_constraint_errors_are_not_hidden(session, project):
    def invalidate_foreign_key(session: Session, context: Any, instances: Any) -> None:
        snapshot = next(row for row in session.new if isinstance(row, SourceSnapshot))
        snapshot.project_id = uuid.uuid4()

    event.listen(session, "before_flush", invalidate_foreign_key, once=True)
    with pytest.raises(IntegrityError):
        create_scan(session, project, _request(), bucket="sources")
    assert session.scalar(select(func.count()).select_from(SourceSnapshot)) == 0
    assert session.scalar(select(func.count()).select_from(Scan)) == 0


@pytest.mark.parametrize("count", [1, 50])
@pytest.mark.parametrize("offset", [0, 100])
def test_unit_list_keeps_queries_bounded_and_leaves_full_evidence_unloaded(
    engine, session, project, count, offset
):
    scan = create_scan(session, project, _request(), bucket="sources")
    scan.reconciler_version = "v1"
    scan.policy_version = "p1"
    units = [
        LocationUnit(
            scan_id=scan.id,
            unit_key=f"{index:04}",
            path=f"{index}.py",
            mapping_status="unmapped",
            reconciler_version="v1",
            locator_version="l1",
        )
        for index in range(count)
    ]
    session.add_all(units)
    session.flush()
    for unit in units:
        session.add(
            UnitAssessment(
                unit_id=unit.id,
                priority="U",
                decision_id="D00",
                reason="fixture",
                policy_id="p",
                policy_version="p1",
                policy_sha256="a" * 64,
                spec_sha256="b" * 64,
                rule_claims_version="v1",
                rule_claims_sha256="c" * 64,
                evidence={"tools": ["semgrep"], "raw": "x" * 32768},
            )
        )
    scan_id = scan.id
    session.commit()

    with Session(engine) as reading:
        scan = reading.get_one(Scan, scan_id)
        queries = []

        @event.listens_for(reading, "do_orm_execute")
        def count_queries(state):
            queries.append(state.statement)

        page = list_units(
            reading, scan, page=PageParams(limit=20, offset=offset), tier=None, tool=None
        )
        assert page.total == count
        assert len(page.items) == (min(count, 20) if offset == 0 else 0)
        assert len(queries) == (3 if page.items else 2)
        assert all(item["tools"] == ["semgrep"] for item in page.items)
        assert not any(isinstance(row, UnitAssessment) for row in reading.identity_map.values())
