import json
import sys
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import build_profile  # noqa: E402

ROOT = build_profile.ROOT


class ProfileTests(unittest.TestCase):
    def test_committed_profile_matches_its_files(self):
        # Fails after any pinned file changes until build_profile.py is rerun and committed.
        self.assertEqual(build_profile.stale(), [])

    def test_compiled_policy_equals_the_yaml_source(self):
        manifest = json.loads((ROOT / build_profile.MANIFEST).read_bytes())
        source = yaml.safe_load((ROOT / manifest["policy"]["source"]).read_bytes())
        compiled = json.loads((ROOT / manifest["policy"]["compiled"]).read_bytes())
        self.assertEqual(compiled, source)

    def test_semgrep_lock_matches_the_pinned_version(self):
        pins = dict(
            line.split("=", 1)
            for line in (ROOT / "tools/pins.env").read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        )
        lock = (ROOT / "tools/requirements-semgrep.lock.txt").read_text(encoding="utf-8")
        self.assertIn(f"\nsemgrep=={pins['SEMGREP_VERSION']}\n", lock)


if __name__ == "__main__":
    unittest.main()
