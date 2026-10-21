"""Observe pre-guard Path.resolve metadata on synthetic workspace-only files.

No application import or execution. Run with Linux Python under WSL from root.
"""

import hashlib
import inspect
import json
import os
from pathlib import Path
import platform
from unittest.mock import patch
from datetime import datetime, timezone


def main():
    workspace = Path.cwd().resolve()
    fixture = workspace / "artifacts/wave-c/self-review-metadata-001"
    fixture.mkdir(exist_ok=False)
    allowed = fixture / "allowed"
    outside = fixture / "outside"
    allowed.mkdir()
    outside.mkdir()
    (outside / "marker.txt").write_text("SYNTHETIC_METADATA_TARGET", encoding="utf-8")
    real_lstat = os.lstat
    cases = []
    for style in ("download_helper_shape", "generic_helper_shape"):
        calls = []

        def observe(path, *args, **kwargs):
            calls.append(os.fspath(path))
            return real_lstat(path, *args, **kwargs)

        with patch.object(os, "lstat", side_effect=observe):
            if style == "download_helper_shape":
                base = allowed.resolve()
                candidate = (base / "../outside/marker.txt").resolve()
                accepted = candidate.is_relative_to(base)
            else:
                candidate = (allowed / "../outside/marker.txt").resolve()
                base = allowed.resolve()
                try:
                    candidate.relative_to(base)
                    accepted = True
                except ValueError:
                    accepted = False
        observed_outside = str(outside / "marker.txt") in calls
        assert not accepted and observed_outside
        cases.append({
            "shape": style, "guard_accepts": accepted,
            "lstat_synthetic_outside_target_before_guard": observed_outside,
            "lstat_calls": calls,
            "file_content_read_by_this_fixture": False,
            "symlinks_created": False, "concurrent_filesystem_change": False,
        })
    stdlib_path = Path(inspect.getsourcefile(Path.resolve))
    output = workspace / "experiments/wave-c/closeout/self-review/metadata-observation.json"
    with output.open("x", encoding="utf-8") as stream:
        json.dump({
            "created_at": datetime.now(timezone.utc).isoformat(),
            "python_version": platform.python_version(),
            "pathlib_source": str(stdlib_path),
            "pathlib_sha256": hashlib.sha256(stdlib_path.read_bytes()).hexdigest(),
            "classification": "synthetic standard-library observation; not an application exploit or a new CodeQL scan",
            "source_imported_or_executed": False,
            "outside_means": "outside the synthetic allowed directory, still inside the workspace fixture",
            "cases": cases,
            "conclusion": "A later containment rejection does not imply the normalization step performed no earlier filesystem access. This alone does not prove an exploitable vulnerability.",
        }, stream, indent=2)
        stream.write("\n")
    print("Both helper shapes rejected the target after lstat of the synthetic outside target; no content read or application execution.")


if __name__ == "__main__":
    main()
