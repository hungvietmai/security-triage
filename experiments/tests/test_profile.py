import json
import sys
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import build_profile  # noqa: E402

ROOT = build_profile.ROOT


def _pins():
    return dict(
        line.split("=", 1)
        for line in (ROOT / "tools/pins.env").read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    )


class ProfileTests(unittest.TestCase):
    def test_committed_profiles_match_their_files(self):
        # Fails after any pinned file changes until build_profile.py is rerun and committed.
        for manifest in build_profile.MANIFESTS:
            with self.subTest(manifest=manifest):
                self.assertEqual(build_profile.stale(manifest), [])

    def test_compiled_policy_equals_the_yaml_source(self):
        for path in build_profile.MANIFESTS:
            with self.subTest(manifest=path):
                manifest = json.loads((ROOT / path).read_bytes())
                source = yaml.safe_load((ROOT / manifest["policy"]["source"]).read_bytes())
                compiled = json.loads((ROOT / manifest["policy"]["compiled"]).read_bytes())
                self.assertEqual(compiled, source)

    def test_semgrep_lock_matches_the_pinned_version(self):
        lock = (ROOT / "tools/requirements-semgrep.lock.txt").read_text(encoding="utf-8")
        self.assertIn(f"\nsemgrep=={_pins()['SEMGREP_VERSION']}\n", lock)

    def test_screening_tool_locks_match_the_pinned_versions(self):
        pins = _pins()
        bandit = (ROOT / "tools/requirements-bandit.lock.txt").read_text(encoding="utf-8")
        self.assertIn(f"bandit=={pins['BANDIT_VERSION']}", bandit.splitlines())
        # package.json names exact versions; package-lock.json must resolve to the same ones.
        package = json.loads((ROOT / "tools/eslint/package.json").read_bytes())
        lock = json.loads((ROOT / "tools/eslint/package-lock.json").read_bytes())
        self.assertEqual(package["dependencies"]["eslint"], pins["ESLINT_VERSION"])
        for name, version in package["dependencies"].items():
            with self.subTest(package=name):
                self.assertEqual(lock["packages"][f"node_modules/{name}"]["version"], version)
        # The language config repeats the plugin version for readers; keep it true.
        config = json.loads((ROOT / "profiles/command-injection-v0.2/javascript.json").read_bytes())
        plugin = package["dependencies"]["eslint-plugin-security"]
        self.assertEqual(config["eslint"]["plugin"], f"eslint-plugin-security@{plugin}")


if __name__ == "__main__":
    unittest.main()
