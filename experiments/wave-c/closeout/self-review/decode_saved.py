"""Decode existing BQRS with IDs/URLs; no query execution or source extraction.

Run with Linux Python under WSL from the repository root. The output directory
must be new. Original result bytes are preserved and copied for reproduction.
"""

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time
from datetime import datetime, timezone


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    root = Path.cwd().resolve()
    output = root / "experiments/wave-c/closeout/self-review/decoded"
    output.mkdir(exist_ok=False)
    cli = root / "artifacts/toolchains/codeql-2.27.1/codeql/codeql"
    records = []
    for rank in ("03", "08"):
        for name in ("Edges", "Paths"):
            source = root / f"artifacts/wave-c/review-paths-001/{rank}/database/results/security-triage/wave-c-review-paths/Review{name}.bqrs"
            before = digest(source)
            saved = output / f"{rank}-{name.lower()}.bqrs"
            shutil.copyfile(source, saved)
            destination = output / f"{rank}-{name.lower()}.json"
            argv = [str(cli), "bqrs", "decode", str(saved), "--format=json", "--entities=all", f"--output={destination}"]
            started = datetime.now(timezone.utc).isoformat()
            clock = time.monotonic()
            result = subprocess.run(argv, capture_output=True, text=True, timeout=60)
            record = {"argv": argv, "started_at": started, "wall_seconds": time.monotonic() - clock,
                      "exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
                      "source_bqrs": source.relative_to(root).as_posix(), "source_sha256": before,
                      "original_unchanged": digest(source) == before, "copied_sha256": digest(saved)}
            records.append(record)
            if result.returncode != 0 or not record["original_unchanged"]:
                raise RuntimeError(record)
            record["decoded_sha256"] = digest(destination)
            print(f"{rank} {name}: exit {result.returncode}; original unchanged", flush=True)
    (output / "commands.json").write_text(json.dumps({
        "classification": "post-hoc correction of entity serialization; not scanner execution",
        "query_runs": 0, "source_executed": False, "commands": records,
    }, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
