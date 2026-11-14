"""Run trial Semgrep rules on a stored development snapshot, inside the worker container.

    docker compose exec -T -e TRIAL_RULES="$(cat <rules.yaml>)" worker python - <coordinate> \
        < experiments/evaluation/tool-trials/semgrep_trial.py

Prints JSON: for every rule ID, the sorted "path:line" of its matches, and Semgrep's seconds.
Reads the snapshot archive the application stored for `coordinate`; nothing from the snapshot
is executed.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from sqlalchemy import select

from app.core.database import SessionLocal
from app.core.storage import get_s3_client
from app.features.sources.models import SourceSnapshot
from app.scanners.acquisition import unpack

coordinate = sys.argv[1]
with SessionLocal() as session:
    snapshot = session.scalars(
        select(SourceSnapshot).where(
            SourceSnapshot.source_coordinate == coordinate, SourceSnapshot.status == "ready"
        )
    ).first()
if snapshot is None:
    sys.exit(f"No stored snapshot for {coordinate}")

with tempfile.TemporaryDirectory() as folder:
    work = Path(folder)
    archive = work / "source.tgz"
    body = get_s3_client().get_object(Bucket=snapshot.bucket, Key=snapshot.object_key)["Body"]
    archive.write_bytes(body.read())
    repo, commit = coordinate.rsplit("/", 1)[1].split("@")
    root = unpack(
        archive,
        work / "s",
        f"{repo}-{commit}",
        max_unpacked_bytes=200 * 1024 * 1024,
        max_files=20_000,
    )
    rules = work / "rules.yaml"
    rules.write_text(os.environ["TRIAL_RULES"], encoding="utf-8")
    started = time.monotonic()
    run = subprocess.run(
        [
            "semgrep",
            "scan",
            "--metrics=off",
            "--disable-version-check",
            "--disable-nosem",
            "--no-git-ignore",
            "--json",
            "--config",
            str(rules),
            ".",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=900,
        check=False,
    )
    seconds = round(time.monotonic() - started, 1)
    if run.returncode not in (0, 1):
        sys.exit(run.stderr[-2000:])
    output = json.loads(run.stdout)

matches: dict[str, list[str]] = {}
for result in output["results"]:
    rule = result["check_id"].rsplit(".", 1)[-1]
    matches.setdefault(rule, []).append(f"{result['path']}:{result['start']['line']}")
print(
    json.dumps(
        {
            "coordinate": coordinate,
            "snapshot_sha256": snapshot.sha256,
            "seconds": seconds,
            "errors": [error.get("message", "")[:200] for error in output.get("errors", [])][:5],
            "matches": {rule: sorted(set(found)) for rule, found in sorted(matches.items())},
        },
        indent=2,
    )
)
