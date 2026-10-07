"""Test doubles shared by the scan workflow tests: object storage, archives, pipeline, registry."""

import base64
import hashlib
import io
import json
import tarfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from app.scanners.pipeline import PipelineResult
from app.scanners.semgrep import stage_rule
from app.triage.sinks_python import locate_python_sinks

PYTHON_SOURCE = "import os\nos.system(cmd)\n"


class FakeStorage:
    def __init__(self) -> None:
        self.objects: dict[tuple[str, str], bytes] = {}

    def get_object(self, Bucket: str, Key: str) -> dict[str, Any]:  # noqa: N803 (boto3 names)
        return {"Body": io.BytesIO(self.objects[(Bucket, Key)])}

    def put_object(self, Bucket: str, Key: str, Body: bytes) -> None:  # noqa: N803
        self.objects[(Bucket, Key)] = Body


def make_archive(files: dict[str, str], root: str = "src") -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as bundle:
        for name, text in files.items():
            data = text.encode()
            entry = tarfile.TarInfo(f"{root}/{name}")
            entry.size = len(data)
            bundle.addfile(entry, io.BytesIO(data))
    return buffer.getvalue()


def _finding(raw_id: str, tool: str, rule_id: str, region: dict[str, Any], snapshot: str) -> Any:
    return {
        "raw_id": raw_id,
        "tool": tool,
        "snapshot_sha256": snapshot,
        "rule_id": rule_id,
        "reported_path": "app.py",
        "reported_region": region,
        "reported_cwes": ["CWE-78"],
        "message": "command injection",
        "sink_identity": None,
        "mapping_status": "unresolved",
        "technical_verdict": "unresolved",
        "scope_verdict": "unresolved",
        "raw_result": {},
    }


def fake_pipeline(
    status: str = "completed", outputs: list[Path] | None = None
) -> Callable[..., PipelineResult]:
    """Stages the pinned rules like run_semgrep and reports one Semgrep and one CodeQL alert."""

    def run(**kwargs: Any) -> PipelineResult:
        output: Path = kwargs["output"]
        if outputs is not None:
            outputs.append(output)
        for index, rule in enumerate(kwargs["semgrep_rules"]):
            stage_rule(
                rule, output / f"rule-{index}.yaml", repository_root=kwargs["repository_root"]
            )
        (output / "semgrep.sarif").write_text('{"runs": []}\n', encoding="utf-8")
        findings = []
        if status != "failed" and kwargs["language"] == "python":
            source = (kwargs["source"] / "app.py").read_text(encoding="utf-8")
            region = dict(locate_python_sinks("app.py", source)[0]["args"][0]["span"])
            snapshot = kwargs["snapshot_sha256"]
            findings = [
                # Semgrep prefixes rule IDs with the staged config's path.
                _finding(
                    "semgrep:0:0", "semgrep", "tmp.rule-1.dangerous-system-call", region, snapshot
                ),
                _finding("codeql:0:0", "codeql", "py/command-line-injection", region, snapshot),
            ]
        step = {"status": status, "exit_code": 0 if status != "failed" else 2, "argv": ["tool"]}
        return PipelineResult(
            status=status,  # type: ignore[arg-type]
            steps={"semgrep": dict(step), "codeql": dict(step)},  # type: ignore[dict-item]
            findings=findings,
            codeql_query_files=kwargs["codeql_query_sha256"],
            codeql_pack_manifest="name: codeql/queries\n",
        )

    return run


def fake_registry(name: str, version: str, tarball: bytes, *, integrity: str | None = None) -> Any:
    """A fetch() double serving one npm version's metadata and tarball, recording each URL."""
    integrity = integrity or (
        "sha512-" + base64.b64encode(hashlib.sha512(tarball).digest()).decode()
    )
    metadata = {
        "name": name,
        "version": version,
        "dist": {
            "tarball": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz",
            "integrity": integrity,
        },
    }
    fetched: list[str] = []

    def fetch(url: str, max_bytes: int) -> bytes:
        fetched.append(url)
        return tarball if url.endswith(".tgz") else json.dumps(metadata).encode()

    fetch.fetched = fetched  # type: ignore[attr-defined]
    return fetch
