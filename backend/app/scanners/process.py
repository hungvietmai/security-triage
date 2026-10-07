"""Subprocess execution boundary for external scanners."""

from __future__ import annotations

import contextlib
import json
import os
import signal
import subprocess
import time
from collections.abc import Mapping, MutableMapping, Sequence
from pathlib import Path
from typing import Literal, Protocol, TypedDict, cast

ToolName = Literal["semgrep", "codeql"]


class ProcessRecord(TypedDict, total=False):
    argv: list[str]
    status: str
    exit_code: int | None
    error: str
    seconds: float
    raw_findings: int
    sarif_sha256: str


class InvokeCallable(Protocol):
    def __call__(
        self,
        argv: Sequence[str | Path],
        cwd: Path,
        output: Path,
        name: str,
        timeout: float,
        env: Mapping[str, str] | None = None,
    ) -> ProcessRecord: ...


class ToolVersionCallable(Protocol):
    def __call__(
        self,
        binary: str,
        expected: str,
        output: Path,
        tool: ToolName,
        steps: MutableMapping[str, ProcessRecord],
        *,
        working_directory: Path,
        invoke_fn: InvokeCallable,
    ) -> None: ...


def invoke(
    argv: Sequence[str | Path],
    cwd: Path,
    output: Path,
    name: str,
    timeout: float,
    env: Mapping[str, str] | None = None,
) -> ProcessRecord:
    """Run one scanner command in its own process group and preserve logs."""
    process_env = dict(env) if env is not None else os.environ.copy()
    if name.startswith("semgrep"):
        process_env.update(SEMGREP_SEND_METRICS="off", SEMGREP_ENABLE_VERSION_CHECK="0")
        process_env.pop("SEMGREP_APP_TOKEN", None)

    command = [str(item) for item in argv]
    start = time.monotonic()
    record: ProcessRecord = {
        "argv": command,
        "status": "failed",
        "exit_code": None,
    }
    with (
        (output / f"{name}.stdout.log").open("wb") as stdout,
        (output / f"{name}.stderr.log").open("wb") as stderr,
    ):
        try:
            process = subprocess.Popen(
                command,
                cwd=cwd,
                stdout=stdout,
                stderr=stderr,
                env=process_env,
                start_new_session=True,
            )
            try:
                record["exit_code"] = process.wait(timeout=timeout)
                record["status"] = "completed" if record["exit_code"] == 0 else "failed"
            except subprocess.TimeoutExpired:
                # The group may exit between the timeout and the kill; still a timeout.
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                record["status"] = "timeout"
        except OSError as exc:
            record["error"] = str(exc)
    record["seconds"] = round(time.monotonic() - start, 4)
    return record


def tool_version(
    binary: str,
    expected: str,
    output: Path,
    tool: ToolName,
    steps: MutableMapping[str, ProcessRecord],
    *,
    working_directory: Path,
    invoke_fn: InvokeCallable = invoke,
) -> None:
    """Require the exact scanner version before running a scan."""
    argv = [binary, "--version"] if tool == "semgrep" else [binary, "version", "--format=json"]
    record = invoke_fn(argv, working_directory, output, tool + "-version", 60)
    steps[tool + "-version"] = record
    if record["status"] != "completed":
        raise RuntimeError(f"{tool} unavailable; see version logs")

    actual = (output / f"{tool}-version.stdout.log").read_text()
    if tool == "codeql":
        payload = cast(object, json.loads(actual))
        if not isinstance(payload, dict):
            raise ValueError("Invalid CodeQL version output")
        version = cast(dict[object, object], payload).get("version")
        if not isinstance(version, str):
            raise ValueError("Invalid CodeQL version output")
        actual = version
    if actual.strip() != expected:
        raise ValueError(f"{tool} version mismatch: {actual.strip()} != {expected}")
