"""Command-line entry points: OpenAPI export and the Celery smoke task."""

import json

from app.workers.celery_app import ping
from scripts import export_openapi


def test_openapi_export_is_deterministic_json_with_every_route():
    first = export_openapi.export()
    assert first == export_openapi.export()
    assert first.endswith("\n")
    spec = json.loads(first)
    assert set(spec["paths"]) == {
        "/api/v1/health/live",
        "/api/v1/health/ready",
        "/api/v1/projects",
        "/api/v1/projects/{project_id}",
    }
    assert "ErrorResponse" in spec["components"]["schemas"]


def test_openapi_export_writes_an_lf_utf8_file(tmp_path):
    target = tmp_path / "openapi.json"
    export_openapi.main([str(target)])
    content = target.read_bytes()
    assert b"\r\n" not in content
    assert content.decode("utf-8") == export_openapi.export()


def test_openapi_export_defaults_to_stdout(capsys):
    export_openapi.main([])
    assert capsys.readouterr().out == export_openapi.export()


def test_ping_task_runs_without_a_broker():
    assert ping.apply().get() == "pong"
