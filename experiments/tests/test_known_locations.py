"""Focused regressions for KnownLocationTests."""

from __future__ import annotations

# Direct unittest discovery bootstraps the repository and shared backend imports.
# ruff: noqa: E402
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))
import hashlib
import json
import textwrap

from experiments.known_locations import locate_javascript, resolve_pyvul, resolve_secbench
from experiments.make_pair_manifests import sha256
from experiments.patch_hunks import diff_files


class KnownLocationTests(unittest.TestCase):
    def manifest(self):
        return {
            "sink_hint": "a.js:2:1",
            "reference_provenance": ["dataset:fixed-commit"],
            "os_command_execution_basis": "published hint",
            "fix_commit": "a" * 40,
        }

    def test_javascript_parser_resolves_aliases_and_ignores_shadowed_or_fake_calls(self):
        source = (
            "const {exec: run} = require('node:child_process');\nrun(input);\n"
            "function f(run) { run(other); }\nconst text = 'run(cmd)';\n// run(fake);\n"
        )
        output = locate_javascript("a.js", source)
        self.assertEqual(len(output["sinks"]), 1)
        self.assertEqual(output["sinks"][0]["sink_kind"], "child_process.exec")
        locations, unresolved, _ = resolve_secbench(self.manifest(), {"a.js": source.encode()})
        self.assertEqual(len(locations), 1)
        self.assertEqual(unresolved, [])

    def test_javascript_hint_mismatch_or_callback_location_remains_unresolved(self):
        source = (
            "const exec = require('child_process').exec;\n"
            "exec(cmd, () => {\n  const value = 1;\n});\n"
        )
        manifest = self.manifest()
        manifest["sink_hint"] = "a.js:3:3"
        locations, unresolved, _ = resolve_secbench(manifest, {"a.js": source.encode()})
        self.assertEqual(locations, [])
        self.assertEqual(unresolved[0]["status"], "known_location_unresolved")

    def test_pyvul_uses_changed_lines_and_exact_function_labels(self):
        old = "import os\ndef first():\n    os.system(a)\ndef second():\n    os.system(b)\n"
        fixed = old.replace("system(a)", "system(c)").replace("system(b)", "system(d)")
        hunks = diff_files({"a.py": old.encode()}, {"a.py": fixed.encode()})
        segment = "def first():\n    os.system(a)"
        labels = [
            {
                "function_name": "first",
                "normalized_code_before_sha256": hashlib.sha256(
                    textwrap.dedent(segment).strip().encode()
                ).hexdigest(),
            }
        ]
        locations, unresolved, metadata = resolve_pyvul(
            self.manifest(), {"a.py": old.encode()}, hunks, labels=labels
        )
        self.assertEqual(len(locations), 1)
        self.assertEqual(locations[0]["span"]["startLine"], 3)
        self.assertEqual(unresolved, [])
        self.assertEqual(len(metadata["excluded_by_function_labels"]), 1)

    def test_unchanged_sink_in_patch_context_is_not_a_known_location(self):
        old = b"import os\nvalue = 1\nos.system(cmd)\n"
        hunks = diff_files({"a.py": old}, {"a.py": old.replace(b"value = 1", b"value = 2")})
        locations, unresolved, _ = resolve_pyvul(self.manifest(), {"a.py": old}, hunks)
        self.assertEqual(locations, [])
        self.assertEqual(unresolved[0]["status"], "known_location_unresolved")

    def test_parse_failure_is_counted_instead_of_dropped(self):
        old = b"def broken(\n"
        hunks = diff_files({"a.py": old}, {"a.py": b"def valid(): pass\n"})
        locations, unresolved, _ = resolve_pyvul(self.manifest(), {"a.py": old}, hunks)
        self.assertEqual(locations, [])
        self.assertTrue(any("could not parse" in item["reason"] for item in unresolved))

    def test_recorded_three_development_results_have_provenance(self):
        pairs = {
            "pyvul-dwisiswant0-apkleaks-a966e781499f": ("apkleaks/apkleaks.py", 88, "os.system"),
            "secbench-diskusage-ng-0.2.6": ("lib/posix.js", 11, "child_process.exec"),
            "secbench-dns-sync-0.1.0": ("lib/dns-sync.js", 21, "shelljs.exec"),
        }
        for pair_id, (path, line, kind) in pairs.items():
            directory = ROOT / "experiments/pairs" / pair_id
            result = json.loads((directory / "known-locations.json").read_text())
            self.assertEqual(result["status"], "resolved")
            self.assertEqual(result["scanner_invocations"], 0)
            self.assertEqual(result["resolved_location_count"], 1)
            self.assertEqual(result["unresolved_case_count"], 0)
            self.assertEqual(result["patch_hunks_sha256"], sha256(directory / "patch-hunks.json"))
            location = result["locations"][0]
            self.assertEqual(
                (location["path"], location["span"]["startLine"], location["sink_kind"]),
                (path, line, kind),
            )
            self.assertTrue(location["provenance"]["references"])


if __name__ == "__main__":
    unittest.main()
