"""Test doubles shared by the scan workflow tests: object storage, archives, pipeline, registry."""

import base64
import hashlib
import io
import json
import shutil
import tarfile
from collections.abc import Callable
from pathlib import Path
from typing import Any, BinaryIO

from app.scanners.bandit import STAGED_CONFIG
from app.scanners.pipeline import PipelineResult
from app.scanners.provenance import pinned_file
from app.scanners.semgrep import stage_rule
from app.triage.sinks_python import locate_python_sinks

PYTHON_SOURCE = "import os\nos.system(cmd)\n"
# Two path sinks; fake_evidence_pipeline keeps line 2 and lets evidence remove line 3.
PATH_SOURCE = "from flask import request\nopen(request.args['a'])\nopen(request.args['b'])\n"
EVIDENCE_PACK = "rules/codeql/path-traversal-v0.2"


class FakeStorage:
    def __init__(self) -> None:
        self.objects: dict[tuple[str, str], bytes] = {}

    def get_object(self, Bucket: str, Key: str) -> dict[str, Any]:  # noqa: N803 (boto3 names)
        return {"Body": io.BytesIO(self.objects[(Bucket, Key)])}

    def put_object(self, Bucket: str, Key: str, Body: bytes | BinaryIO) -> None:  # noqa: N803
        self.objects[(Bucket, Key)] = Body if isinstance(Body, bytes) else Body.read()


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


def _code_flow(steps: list[dict[str, Any]]) -> dict[str, Any]:
    """A SARIF code flow with one reported path."""
    locations = [
        {
            "location": {
                "physicalLocation": {
                    "artifactLocation": {"uri": step["uri"]},
                    "region": {"startLine": step["line"], "startColumn": 1},
                }
            }
        }
        for step in steps
    ]
    return {"threadFlows": [{"locations": locations}]}


def fake_pipeline(
    status: str = "completed",
    outputs: list[Path] | None = None,
    *,
    semgrep_rule: str = "dangerous-system-call",
    refuted: bool = False,
    codeql_alert: bool = True,
    bandit_severity: str | None = None,
    dead_branch: bool = False,
) -> Callable[..., PipelineResult]:
    """Stages the pinned rules like run_semgrep and reports one Semgrep and one CodeQL alert.

    When the language config configures Bandit, it also stages the pinned ini like
    run_bandit and reports one Bandit alert on the whole call. When it configures CodeQL
    evidence queries, the control query repeats the CodeQL alert and the evidence query
    repeats it too unless `refuted`. `semgrep_rule` names the pinned Semgrep rule that
    reports: "dangerous-system-call" claims a flow, "subprocess-shell-true" is an audit.
    `codeql_alert=False` leaves CodeQL silent; `bandit_severity` is the rating Bandit gives
    the call (LOW for a literal command). When the config configures Semgrep evidence
    rules, the control rule reports the command and the evidence rule repeats it unless
    `dead_branch`, in which case line 1 is reported as a dead assignment and CodeQL's
    alert carries a path through it.
    """

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
                _finding("semgrep:0:0", "semgrep", f"tmp.{semgrep_rule}", region, snapshot),
                _finding("codeql:0:0", "codeql", "py/command-line-injection", region, snapshot),
            ][: 2 if codeql_alert else 1]
        step = {"status": status, "exit_code": 0 if status != "failed" else 2, "argv": ["tool"]}
        steps = {"semgrep": dict(step), "codeql": dict(step)}
        bandit = kwargs.get("bandit")
        if bandit is not None:
            steps["bandit"] = dict(step)
            root = kwargs["repository_root"]
            shutil.copyfile(pinned_file(bandit["config"], root), output / STAGED_CONFIG)
            if findings:
                call = dict(locate_python_sinks("app.py", source)[0]["span"])
                bandit_alert = _finding("bandit:0:0", "bandit", "B605", call, snapshot)
                if bandit_severity is not None:
                    bandit_alert["raw_result"] = {"properties": {"issue_severity": bandit_severity}}
                findings.append(bandit_alert)
        evidence_findings: list[Any] = []
        if kwargs.get("semgrep_evidence") is not None:
            steps["semgrep-evidence"] = dict(step)
            (output / "semgrep-evidence.sarif").write_text('{"runs": []}\n', encoding="utf-8")
            if findings:
                reported = [("st-cmd-flow-none", region)]
                if dead_branch:
                    line: dict[str, Any] = {
                        "startLine": 1,
                        "startColumn": 1,
                        "endLine": 1,
                        "endColumn": 10,
                    }
                    reported.append(("st-dead-assignment", line))
                    path = [{"uri": "app.py", "line": 1}, {"uri": "app.py", "line": 2}]
                    for finding in findings:
                        if finding["tool"] == "codeql":
                            finding["raw_result"] = {"codeFlows": [_code_flow(path)]}
                else:
                    reported.append(("st-cmd-flow-all", region))
                evidence_findings += [
                    _finding(
                        f"semgrep-evidence:0:{index}",
                        "semgrep-evidence",
                        f"tmp.semgrep-evidence.{rule}",
                        where,
                        snapshot,
                    )
                    for index, (rule, where) in enumerate(reported)
                ]
        if kwargs.get("codeql_evidence") is not None:
            steps["codeql-evidence"] = dict(step)
            (output / "codeql-evidence.sarif").write_text('{"runs": []}\n', encoding="utf-8")
            if findings and codeql_alert:
                rules = ["st/cwe-78/none"] + ([] if refuted else ["st/cwe-78/all"])
                evidence_findings += [
                    _finding(
                        f"codeql-evidence:0:{index}", "codeql-evidence", rule, region, snapshot
                    )
                    for index, rule in enumerate(rules)
                ]
        return PipelineResult(
            status=status,  # type: ignore[arg-type]
            steps=steps,  # type: ignore[arg-type]
            findings=findings,
            codeql_query_files=kwargs["codeql_query_sha256"],
            codeql_pack_manifest="name: codeql/queries\n",
            evidence_findings=evidence_findings,
        )

    return run


def fake_evidence_pipeline(status: str = "completed") -> Callable[..., PipelineResult]:
    """CodeQL from the pinned evidence pack: baseline alerts on lines 2 and 3, evidence on 2."""

    def run(**kwargs: Any) -> PipelineResult:
        assert kwargs["scanners"] == ["codeql"]
        assert kwargs["python_query_pack"].as_posix().endswith(EVIDENCE_PACK)
        snapshot = kwargs["snapshot_sha256"]

        def alert(raw_id: str, rule_id: str, line: int) -> Any:
            region = {"startLine": line, "startColumn": 6, "endLine": line, "endColumn": 24}
            return {
                **_finding(raw_id, "codeql", rule_id, region, snapshot),
                "reported_cwes": ["CWE-22"],
                "message": "flow from source",
            }

        findings = []
        if status != "failed":
            findings = [
                alert("codeql:0:0", "st/cwe-22/none", 2),
                alert("codeql:0:1", "st/cwe-22/none", 3),
                alert("codeql:0:2", "st/cwe-22/all", 2),
            ]
        step = {"status": status, "exit_code": 0 if status != "failed" else 2, "argv": ["codeql"]}
        return PipelineResult(
            status=status,  # type: ignore[arg-type]
            steps={"codeql": step},  # type: ignore[dict-item]
            findings=findings,
            codeql_query_files=kwargs["codeql_query_sha256"],
            codeql_pack_manifest="name: security-triage/python-safety-evidence\n",
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
