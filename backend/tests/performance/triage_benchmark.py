"""Manual triage benchmark: synthetic inputs, no scanner execution or dependency downloads."""

import hashlib
import json
import statistics
import time
from pathlib import Path

from app.scanners.profile import load_profile
from app.triage.assess import assess_units
from app.triage.policy import validate_policy
from app.triage.reconcile import reconcile_findings
from app.triage.sinks_python import locate_python_sinks

ROOT = Path(__file__).resolve().parents[3]
profile = load_profile(ROOT, "profiles/command-injection-v0.1/profile.json")
policy = validate_policy(profile.policy)


def inputs(count, layout):
    if layout == "repeated_sink":
        sources = {"app.py": "import os\nos.system(command)\n"}
    elif layout == "single_file":
        sources = {"app.py": "import os\n" + "os.system(command)\n" * count}
    else:
        sources = {f"files/{i:05}.py": "import os\nos.system(command)\n" for i in range(count)}
    sinks = [s for path, source in sources.items() for s in locate_python_sinks(path, source)]
    findings = []
    for i in range(count):
        sink = sinks[0] if layout == "repeated_sink" else sinks[i]
        findings.append(
            {
                "raw_id": f"semgrep:0:{i}",
                "tool": "semgrep",
                "rule_id": "unknown.rule",
                "reported_path": sink["path"],
                "snapshot_sha256": "a" * 64,
                "reported_region": sink["args"][0]["span"],
                "raw_result": {},
            }
        )
    return findings, sinks, sources


def run(count, layout):
    findings, sinks, sources = inputs(count, layout)
    reconcile_times, assess_times = [], []
    units, assessments = [], []
    for _ in range(3):
        start = time.perf_counter()
        units = reconcile_findings(findings, sinks, sources)
        reconcile_times.append(time.perf_counter() - start)
        start = time.perf_counter()
        assessments = assess_units(
            units,
            findings,
            sinks,
            sources,
            mapping=profile.rule_claims,
            definitions=[],
            policy=policy,
            provenance={},
        )
        assess_times.append(time.perf_counter() - start)
    digest = hashlib.sha256(json.dumps([units, assessments], sort_keys=True).encode()).hexdigest()
    return {
        "layout": layout,
        "findings": count,
        "units": len(units),
        "reconcile_ms": round(statistics.median(reconcile_times) * 1000, 3),
        "assess_ms": round(statistics.median(assess_times) * 1000, 3),
        "sha256": digest,
    }


def main():
    results = [
        run(count, layout)
        for layout in ("distributed", "single_file", "repeated_sink")
        for count in (100, 1000, 5000)
    ]
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
