"""CLI selection workflows with synthetic metadata only; no research source or scanners."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "experiments/wave-c/select_repositories.py"


class WaveCSelectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = [
            self.advisory("GHSA-synthetic-1", "example/one", "1" * 40),
            self.advisory("GHSA-synthetic-2", "Example/ONE", "2" * 40),
            self.advisory("GHSA-synthetic-3", "example/old-held-out", "3" * 40),
            self.advisory("GHSA-synthetic-4", "example/two", "4" * 40),
            self.advisory("GHSA-synthetic-5", "example/short", "abc1234"),
        ]
        self.config = {
            "seed": "synthetic/",
            "sample_size": 2,
            "source_commit": "a" * 40,
            "exclusions": self.write_json(
                "exclusions.json",
                {
                    "inputs": [],
                    "repositories": [
                        {"repository": "example/old-held-out", "reasons": ["old split"]}
                    ],
                },
            ),
            "protocol": self.write("protocol.md", b"Synthetic selection protocol\n"),
        }
        self.update_source()

    @staticmethod
    def advisory(identifier, repository, commit):
        return {
            "ghsa_id": identifier,
            "decision": "candidate",
            "cwes": ["CWE-22"],
            "fix_commits": [f"https://github.com/{repository}/commit/{commit}"],
        }

    def write(self, name, data):
        (self.root / name).write_bytes(data)
        return {"path": name, "sha256": hashlib.sha256(data).hexdigest()}

    def write_json(self, name, value):
        return self.write(name, json.dumps(value).encode())

    def update_source(self):
        self.config["advisories"] = self.write_json("source.json", self.source)
        self.write_json("config.json", self.config)

    def run_cli(self, *extra):
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--root",
                str(self.root),
                "--config",
                "config.json",
                "--output",
                "inventory.json",
                *extra,
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_select_group_exclude_and_reproduce_without_mutation(self):
        result = self.run_cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        original = (self.root / "inventory.json").read_bytes()
        inventory = json.loads(original)
        self.assertEqual(inventory["selected_repositories"], 2)
        self.assertEqual(
            {r["repository"] for r in inventory["candidates"]}, {"example/one", "example/two"}
        )
        grouped = next(r for r in inventory["candidates"] if r["repository"] == "example/one")
        self.assertEqual(len(grouped["references"]), 2)
        self.assertEqual(
            inventory["excluded_repositories"][0]["repository"], "example/old-held-out"
        )
        self.assertEqual(len(inventory["rejected_references"]), 1)
        self.assertEqual(self.run_cli("--check").returncode, 0)
        self.assertNotEqual(self.run_cli().returncode, 0)  # Never overwrite an existing draw.
        self.assertEqual((self.root / "inventory.json").read_bytes(), original)

    def test_input_reordering_preserves_draw_and_anchor(self):
        self.assertEqual(self.run_cli().returncode, 0)
        before = json.loads((self.root / "inventory.json").read_bytes())["candidates"]
        (self.root / "inventory.json").unlink()
        self.source.reverse()
        self.update_source()
        self.assertEqual(self.run_cli().returncode, 0)
        after = json.loads((self.root / "inventory.json").read_bytes())["candidates"]
        self.assertEqual(after, before)

    def test_changed_inputs_and_inventory_fail_closed(self):
        self.assertEqual(self.run_cli().returncode, 0)
        original = (self.root / "inventory.json").read_bytes()
        (self.root / "inventory.json").write_bytes(original + b" ")
        self.assertIn("differs", self.run_cli("--check").stderr)
        self.write_json("source.json", [])  # Do not update the pinned configuration.
        result = self.run_cli("--check")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("hash mismatch", result.stderr)


if __name__ == "__main__":
    unittest.main()
