"""Manual benchmark of run-local caching and parallel uploads with simulated network delay."""

import hashlib
import json
import statistics
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, BinaryIO

from app.scanners.profile import load_profile
from app.triage.claims import classify_claims
from app.workflows.scans.task import _upload

ROOT = Path(__file__).resolve().parents[3]
DELAY_SECONDS = 0.02


class SimulatedStorage:
    def put_object(self, *, Bucket: str, Key: str, Body: BinaryIO) -> None:
        time.sleep(DELAY_SECONDS)
        while Body.read(64 * 1024):
            pass


def main():
    profile = load_profile(ROOT, "profiles/command-injection-v0.1/profile.json")
    mapping = profile.rule_claims
    rule = mapping["rules"][0]
    fields = list(mapping["identity_fields"])
    if rule["tool"] == "codeql":
        fields += mapping["codeql_additional_identity_fields"]
    definitions = [{key: rule[key] for key in fields}]
    findings = [
        {"raw_id": f"finding:{index}", "tool": rule["tool"], "rule_id": rule["rule_id"]}
        for index in range(10000)
    ]
    cache_times: list[float] = []
    claims: list[dict[str, Any]] = []
    for _ in range(5):
        start = time.perf_counter()
        claims = classify_claims(mapping, findings, definitions)
        cache_times.append((time.perf_counter() - start) * 1000)
    results = [
        {
            "case": "repeated_claims",
            "findings": len(findings),
            "median_ms": round(statistics.median(cache_times), 3),
            "sha256": hashlib.sha256(json.dumps(claims, sort_keys=True).encode()).hexdigest(),
        }
    ]
    with tempfile.TemporaryDirectory() as folder:
        output = Path(folder)
        for index in range(8):
            (output / f"{index}.log").write_bytes(b"benchmark")
        checksums = []
        for workers in (1, 4):
            timings: list[float] = []
            artifacts: dict[str, dict[str, Any]] = {}
            for _ in range(3):
                start = time.perf_counter()
                artifacts = _upload(
                    SimulatedStorage(),  # type: ignore[arg-type]
                    "unused",
                    uuid.UUID(int=0),
                    "python",
                    output,
                    workers=workers,
                )
                timings.append((time.perf_counter() - start) * 1000)
            checksum = hashlib.sha256(json.dumps(artifacts, sort_keys=True).encode()).hexdigest()
            checksums.append(checksum)
            results.append(
                {
                    "case": "simulated_upload_latency",
                    "files": 8,
                    "workers": workers,
                    "simulated_delay_ms": DELAY_SECONDS * 1000,
                    "median_ms": round(statistics.median(timings), 3),
                    "sha256": checksum,
                }
            )
        assert checksums[0] == checksums[1]
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
