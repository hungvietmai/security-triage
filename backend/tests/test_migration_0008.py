"""Migration 0008 on a database that already holds results: nothing stored is rewritten.

The test database is created at the current schema, taken back to revision 0007 with the
migration's own downgrade, filled with rows as revision 0007 stored them, and upgraded again.
"""

import importlib.util
import uuid
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import Engine, inspect, text
from sqlalchemy.orm import Session

from app.features.triage.models import LocationUnit

MIGRATION = Path(__file__).resolve().parents[1] / "migrations/versions/0008_unit_analysis_family.py"


def _migration():
    spec = importlib.util.spec_from_file_location("migration_0008", MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(engine: Engine, step: str) -> None:
    migration = _migration()
    with engine.begin() as connection:
        operations = Operations(MigrationContext.configure(connection))
        # The migration calls the module-level `op`; point it at this connection.
        migration.op = operations
        getattr(migration, step)()


def _columns(engine: Engine) -> set[str]:
    return {column["name"] for column in inspect(engine).get_columns("location_units")}


def test_upgrade_adds_a_nullable_family_and_keeps_stored_units(engine: Engine):
    migration = _migration()
    assert (migration.revision, migration.down_revision) == ("0008", "0007")

    _run(engine, "downgrade")
    assert "analysis_family" not in _columns(engine)
    indexes = {index["name"] for index in inspect(engine).get_indexes("location_units")}
    assert "ix_location_units_analysis_family" not in indexes

    # Rows as revision 0007 wrote them: a project, a snapshot, a scan and two of its units.
    ids = {name: uuid.uuid4().hex for name in ("project", "snapshot", "scan", "one", "two")}
    with engine.begin() as connection:
        dialect = connection.dialect.name

        def identifier(name: str) -> str:
            # PostgreSQL stores UUIDs; SQLite stores their 32 hexadecimal characters.
            return str(uuid.UUID(ids[name])) if dialect == "postgresql" else ids[name]

        connection.execute(
            text("INSERT INTO projects (id, name) VALUES (:id, 'Before 0008')"),
            {"id": identifier("project")},
        )
        connection.execute(
            text(
                "INSERT INTO source_snapshots (id, project_id, bucket, object_key, status) "
                "VALUES (:id, :project, 'b', 'k', 'ready')"
            ),
            {"id": identifier("snapshot"), "project": identifier("project")},
        )
        connection.execute(
            text(
                "INSERT INTO scans (id, snapshot_id, status, config, artifacts, "
                "reconciler_version, policy_version) VALUES (:id, :snapshot, 'completed', "
                "'{\"profile_id\": \"command-injection-v0.2\"}', '{}', 'reconcile-v0.1', '0.2')"
            ),
            {"id": identifier("scan"), "snapshot": identifier("snapshot")},
        )
        for name, key, candidate in (("one", "a" * 64, "c" * 64), ("two", "b" * 64, None)):
            connection.execute(
                text(
                    "INSERT INTO location_units (id, scan_id, unit_key, path, start_line, "
                    "mapping_status, reconciler_version, locator_version, candidate_key) VALUES "
                    "(:id, :scan, :key, 'app.py', 3, 'mapped', 'reconcile-v0.1', "
                    "'sink-locator-v0', :candidate)"
                ),
                {
                    "id": identifier(name),
                    "scan": identifier("scan"),
                    "key": key,
                    "candidate": candidate,
                },
            )
        before = connection.execute(
            text(
                "SELECT unit_key, path, start_line, mapping_status, reconciler_version, "
                "locator_version, candidate_key FROM location_units ORDER BY unit_key"
            )
        ).all()

    _run(engine, "upgrade")
    assert "analysis_family" in _columns(engine)
    indexes = {index["name"] for index in inspect(engine).get_indexes("location_units")}
    assert "ix_location_units_analysis_family" in indexes
    with engine.begin() as connection:
        after = connection.execute(
            text(
                "SELECT unit_key, path, start_line, mapping_status, reconciler_version, "
                "locator_version, candidate_key FROM location_units ORDER BY unit_key"
            )
        ).all()
        families = connection.execute(text("SELECT analysis_family FROM location_units")).all()
    # Every stored value is what it was, and the new column is empty for old rows.
    assert after == before and len(after) == 2
    assert {family for (family,) in families} == {None}

    # The current models read the old rows, and a new row can carry a family.
    with Session(engine) as session:
        units = session.query(LocationUnit).order_by(LocationUnit.unit_key).all()
        assert [(unit.unit_key, unit.analysis_family) for unit in units] == [
            ("a" * 64, None),
            ("b" * 64, None),
        ]
        session.add(
            LocationUnit(
                scan_id=units[0].scan_id,
                unit_key="d" * 64,
                mapping_status="mapped",
                reconciler_version="safety-evidence-units-v1",
                locator_version="codeql-reported-location",
                analysis_family="path-traversal",
            )
        )
        session.commit()

    # Going back and forward again loses only the column this revision added.
    _run(engine, "downgrade")
    with engine.begin() as connection:
        assert connection.execute(text("SELECT count(*) FROM location_units")).scalar() == 3
    _run(engine, "upgrade")
