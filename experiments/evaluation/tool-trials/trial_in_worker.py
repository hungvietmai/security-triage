"""Tool-selection trial, run inside the worker container on a stored development snapshot.

    docker compose exec -T -e TRIAL_RULE="$(cat <rule.yaml>)" worker python - <coordinate> \
        < experiments/evaluation/tool-trials/trial_in_worker.py

Reads the snapshot archive the application already stored for `coordinate`, unpacks it with
the worker's own bounded extractor, and runs the trial Semgrep rule (piped in as the
TRIAL_RULE environment variable) and Bandit on it. Prints JSON: per file, which tool gave
"constant command" evidence, and the seconds each tool took. Nothing is executed from the
snapshot and nothing is written outside a temporary directory.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from sqlalchemy import select

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.core.storage import get_s3_client
from app.features.sources.models import SourceSnapshot
from app.scanners.acquisition import unpack

coordinate = sys.argv[1]
settings = get_settings()
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
    source = work / "source"
    # github:<owner>/<repo>@<commit> archives unpack to <repo>-<commit>.
    repo, commit = coordinate.rsplit("/", 1)[1].split("@")
    root = unpack(
        archive, source, f"{repo}-{commit}", max_unpacked_bytes=200 * 1024 * 1024, max_files=20_000
    )
    rule = work / "rule.yaml"
    rule.write_text(os.environ["TRIAL_RULE"], encoding="utf-8")

    started = time.monotonic()
    semgrep = subprocess.run(
        [
            "semgrep",
            "scan",
            "--metrics=off",
            "--disable-version-check",
            "--disable-nosem",
            "--no-git-ignore",
            "--json",
            "--config",
            str(rule),
            ".",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=900,
        check=False,
    )
    semgrep_seconds = round(time.monotonic() - started, 1)
    constant = sorted({r["path"] for r in json.loads(semgrep.stdout)["results"]})

    started = time.monotonic()
    ini = work / "bandit.ini"
    ini.write_text("[bandit]\n", encoding="utf-8")
    report = work / "bandit.json"
    subprocess.run(
        [
            "bandit",
            "--recursive",
            ".",
            "--format",
            "json",
            "--output",
            str(report),
            "--ini",
            str(ini),
            "--tests",
            "B602,B605",
            "--ignore-nosec",
            "--exit-zero",
            "--quiet",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=900,
        check=False,
    )
    bandit_seconds = round(time.monotonic() - started, 1)
    issues = json.loads(report.read_text(encoding="utf-8"))["results"]
    literal = sorted(
        {i["filename"].removeprefix("./") for i in issues if i["issue_severity"] == "LOW"}
    )
    built = sorted(
        {i["filename"].removeprefix("./") for i in issues if i["issue_severity"] != "LOW"}
    )

print(
    json.dumps(
        {
            "coordinate": coordinate,
            "snapshot_sha256": snapshot.sha256,
            "semgrep_constant_command_files": constant,
            "semgrep_seconds": semgrep_seconds,
            "bandit_literal_command_files": literal,
            "bandit_built_command_files": len(built),
            "bandit_seconds": bandit_seconds,
        },
        indent=2,
    )
)
