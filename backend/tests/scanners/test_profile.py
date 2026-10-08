import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from app.scanners.profile import ProfileError, load_profile

ROOT = Path(__file__).resolve().parents[3]
MANIFEST = "profiles/command-injection-v0.1/profile.json"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_profile(root: Path, *, rule_sha: str | None = None) -> dict[str, Any]:
    files = {
        "rules/r.yaml": b"rules: []\n",
        "policy.yaml": b"policy_id: p\n",
        "policy.json": b'{"policy_id": "p"}\n',
        "spec.md": b"# spec\n",
        "claims.json": b'{"version": "c"}\n',
        "locator.yaml": b"rules: []\n",
    }
    config = {
        "semgrep_rules": [
            {"path": "rules/r.yaml", "sha256": rule_sha or _sha(files["rules/r.yaml"])}
        ]
    }
    files["js.json"] = json.dumps(config).encode()
    for relative, data in files.items():
        (root / relative).parent.mkdir(parents=True, exist_ok=True)
        (root / relative).write_bytes(data)
    manifest: dict[str, Any] = {
        "profile_id": "test-profile",
        "languages": {"javascript": {"config": "js.json", "sink_locator": "locator.yaml"}},
        "policy": {"source": "policy.yaml", "compiled": "policy.json"},
        "specification": "spec.md",
        "rule_claims": "claims.json",
        "semgrep_rule_ids": {"rules/r.yaml": "r"},
        "files": {relative: _sha(data) for relative, data in files.items()},
    }
    (root / "profile.json").write_text(json.dumps(manifest), encoding="utf-8")
    return manifest


def test_load_profile_returns_verified_contents(tmp_path):
    _write_profile(tmp_path)
    profile = load_profile(tmp_path, "profile.json")
    assert profile.profile_id == "test-profile"
    assert profile.manifest_sha256 == _sha((tmp_path / "profile.json").read_bytes())
    assert profile.policy == {"policy_id": "p"}
    assert profile.policy_sha256 == _sha(b"policy_id: p\n")  # the YAML, not the JSON
    assert profile.rule_claims == {"version": "c"}
    assert profile.semgrep_rule_ids == {"rules/r.yaml": "r"}
    assert profile.sink_locators == {"javascript": tmp_path.resolve() / "locator.yaml"}


def test_load_profile_rejects_changed_bytes(tmp_path):
    _write_profile(tmp_path)
    (tmp_path / "rules/r.yaml").write_bytes(b"rules: [changed]\n")
    with pytest.raises(ProfileError, match="hash mismatch: rules/r.yaml"):
        load_profile(tmp_path, "profile.json")


def test_load_profile_rejects_unpinned_missing_and_escaping_files(tmp_path):
    manifest = _write_profile(tmp_path)
    files = manifest["files"]

    del files["spec.md"]
    (tmp_path / "profile.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ProfileError, match="does not pin spec.md"):
        load_profile(tmp_path, "profile.json")

    files["gone.yaml"] = "0" * 64
    (tmp_path / "profile.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ProfileError, match="unreadable: gone.yaml"):
        load_profile(tmp_path, "profile.json")

    with pytest.raises(ProfileError, match="escapes"):
        load_profile(tmp_path / "rules", "../profile.json")


def test_load_profile_rejects_config_rule_pin_disagreement(tmp_path):
    _write_profile(tmp_path, rule_sha="f" * 64)
    with pytest.raises(ProfileError, match="pin rules/r.yaml differently"):
        load_profile(tmp_path, "profile.json")


def test_load_profile_requires_a_rule_id_for_every_config_rule(tmp_path):
    manifest = _write_profile(tmp_path)
    manifest["semgrep_rule_ids"] = {}
    (tmp_path / "profile.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ProfileError, match="no rule ID for rules/r.yaml"):
        load_profile(tmp_path, "profile.json")


def test_load_profile_rejects_malformed_manifest(tmp_path):
    (tmp_path / "profile.json").write_text('{"files": {}}', encoding="utf-8")
    with pytest.raises(ProfileError, match="Malformed"):
        load_profile(tmp_path, "profile.json")


def test_repository_profile_verifies():
    profile = load_profile(ROOT, MANIFEST)
    assert profile.profile_id == "command-injection-v0.1"
    assert set(profile.configs) == {"javascript", "python"}
    assert all(config["jobs"] == 1 for config in profile.configs.values())
    assert profile.policy["policy_version"] == "0.1"
