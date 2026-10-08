"""CLI integration: manifests → locked bytes → persisted patch and location evidence."""

from __future__ import annotations

# Direct unittest discovery bootstraps the repository before shared imports.
# ruff: noqa: E402
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from experiments.lock_pair_sources import lock_sources
from experiments.make_pair_manifests import sha256
from experiments.tests.archive_fixtures import archive_bytes

from app.scanners.sources import FetchedArchive

PAIR_ID = "pyvul-dwisiswant0-apkleaks-a966e781499f"


class PairPipelineIntegrationTests(unittest.TestCase):
    def cli(self, script, *arguments):
        result = subprocess.run(
            [sys.executable, str(ROOT / "experiments" / script), *map(str, arguments)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def prepare(self, directory):
        self.cli("make_pair_manifests.py", "--output", directory)
        manifest = json.loads((directory / f"{PAIR_ID}.json").read_text())
        vulnerable = b"import os\ndef run(cmd):\n    os.system(cmd)\n"
        fixed = b"import os\ndef run(cmd):\n    os.system('true')\n"

        def download(source):
            root = f"apkleaks-{source['commit']}"
            content = vulnerable if source["commit"] == manifest["vulnerable_ref"] else fixed
            data = archive_bytes(
                {
                    "app.py": content,
                    "tests/test_app.py": b"test fixture",
                    "README.md": b"documentation",
                },
                root=root,
            )
            return FetchedArchive(
                data,
                hashlib.sha256(data).hexdigest(),
                f"https://codeload.github.com/{source['repository']}/tar.gz/{source['commit']}",
                "tofu",
                root,
            )

        cache = directory / "cache"
        locks = lock_sources([manifest], directory, cache, download_fn=download)
        return cache, locks

    def test_cli_pipeline_preserves_source_identity_and_writes_reviewable_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            cache, locks = self.prepare(directory)
            self.cli("patch_hunks.py", "--pair", PAIR_ID, "--pairs", directory, "--cache", cache)
            result = self.cli(
                "known_locations.py", "--pair", PAIR_ID, "--pairs", directory, "--cache", cache
            )
            summary = json.loads(result.stdout)
            self.assertEqual(summary["pairs_resolved"], 1)
            self.assertEqual(summary["scanner_invocations"], 0)
            patch_path = directory / PAIR_ID / "patch-hunks.json"
            patch = json.loads(patch_path.read_text())
            known = json.loads((directory / PAIR_ID / "known-locations.json").read_text())
            hashes = {
                version: locks[PAIR_ID][version]["sha256"] for version in ("vulnerable", "fixed")
            }
            self.assertEqual(patch["snapshot_sha256"], hashes)
            self.assertEqual(known["snapshot_sha256"], hashes)
            self.assertEqual(known["patch_hunks_sha256"], sha256(patch_path))
            self.assertEqual(known["locations"][0]["span"]["startLine"], 3)
            self.assertEqual(known["locations"][0]["sink_kind"], "os.system")
            self.assertEqual(
                {item["reason"] for item in patch["ignored"]["vulnerable"]},
                {"documentation", "test_directory"},
            )

    def test_cli_rejects_missing_cache_instead_of_reacquiring_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            cache, _ = self.prepare(directory)
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "experiments/patch_hunks.py"),
                    "--pair",
                    PAIR_ID,
                    "--pairs",
                    str(directory),
                    "--cache",
                    str(cache / "missing"),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=30,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("FileNotFoundError", result.stderr)
            self.assertFalse((directory / PAIR_ID / "patch-hunks.json").exists())


if __name__ == "__main__":
    unittest.main()
