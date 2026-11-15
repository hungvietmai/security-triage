"""Composite profiles: a manifest that pins member manifests, one per analysis family."""

import json
from pathlib import Path
from typing import Any

import pytest

from app.scanners.profile import (
    CompositeProfile,
    EvidenceProfile,
    ProfileError,
    ScanProfile,
    load_any_profile,
    load_composite_profile,
    load_member_profile,
)
from tests.scanners.test_profile import ROOT, _sha, _write_evidence_profile, _write_profile

MANIFEST = "profiles/multi-cwe-v0.1/profile.json"
# The loader only requires a composition to be named; the worker checks which ones it runs.
COMPOSITION_VERSION = "family-composition-v0.1"


def _write_composite(root: Path, **changes: Any) -> dict[str, Any]:
    """Two synthetic member profiles under `root` and a composite manifest that pins them."""
    _write_profile(root)
    (root / "profile.json").rename(root / "priority.json")
    _write_evidence_profile(root)
    (root / "profile.json").rename(root / "evidence.json")
    (root / "composition.md").write_bytes(b"# composition\n")
    manifest: dict[str, Any] = {
        "schema": 2,
        "kind": "composite",
        "profile_id": "composite-test",
        "composition": COMPOSITION_VERSION,
        "members": [
            {
                "family": "command-injection",
                "profile_id": "test-profile",
                "profile": "priority.json",
            },
            {"family": "path-traversal", "profile_id": "evidence", "profile": "evidence.json"},
        ],
        "specification": "composition.md",
        "files": {
            name: _sha((root / name).read_bytes())
            for name in ("priority.json", "evidence.json", "composition.md")
        },
        **changes,
    }
    (root / "composite.json").write_text(json.dumps(manifest), encoding="utf-8")
    return manifest


def test_a_composite_profile_loads_each_pinned_member_with_its_own_loader(tmp_path):
    _write_composite(tmp_path)
    profile = load_any_profile(tmp_path, "composite.json")

    assert isinstance(profile, CompositeProfile)
    assert profile.profile_id == "composite-test"
    assert profile.manifest_sha256 == _sha((tmp_path / "composite.json").read_bytes())
    assert profile.specification_sha256 == _sha(b"# composition\n")
    assert profile.composition == COMPOSITION_VERSION
    (first_family, first), (second_family, second) = profile.members
    assert (first_family, second_family) == ("command-injection", "path-traversal")
    assert isinstance(first, ScanProfile) and isinstance(second, EvidenceProfile)
    # A member is the profile it is alone: same manifest hash, same verified contents.
    assert first.manifest_sha256 == _sha((tmp_path / "priority.json").read_bytes())
    assert first == load_member_profile(tmp_path, "priority.json")
    # The scan's languages are those of the member that runs the scanners.
    assert profile.configs is first.configs and set(profile.configs) == {"javascript"}


def test_a_member_manifest_that_changed_after_pinning_is_refused(tmp_path):
    _write_composite(tmp_path)
    member = json.loads((tmp_path / "evidence.json").read_text(encoding="utf-8"))
    member["baseline_rule"] = "st/other"
    (tmp_path / "evidence.json").write_text(json.dumps(member), encoding="utf-8")
    with pytest.raises(ProfileError, match="Profile hash mismatch: evidence.json"):
        load_composite_profile(tmp_path, "composite.json")


def test_a_member_whose_own_pins_no_longer_match_is_refused(tmp_path):
    _write_composite(tmp_path)
    (tmp_path / "pack/q/all.ql").write_bytes(b"select 3\n")
    with pytest.raises(ProfileError, match="Profile hash mismatch: pack/q/all.ql"):
        load_composite_profile(tmp_path, "composite.json")


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda m: m.update(schema=1), "Not a composite profile of schema 2"),
        (lambda m: m.update(members=[]), "at least one member"),
        (lambda m: m["members"][1].update(profile_id="another"), "is not profile another"),
        (lambda m: m["members"][1].update(family="command-injection"), "one member per analysis"),
        (lambda m: m["members"][1].update(family=""), "needs an analysis family"),
        (lambda m: m["files"].pop("evidence.json"), "does not pin evidence.json"),
        (lambda m: m.update(composition=""), "names its composition version"),
        (lambda m: m.pop("specification"), "Malformed scan profile"),
        (lambda m: m["members"][0].update(profile="../outside.json"), "does not pin"),
    ],
)
def test_malformed_composite_manifests_are_refused(tmp_path, change, message):
    manifest = _write_composite(tmp_path)
    change(manifest)
    (tmp_path / "composite.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ProfileError, match=message):
        load_composite_profile(tmp_path, "composite.json")


def test_a_composite_profile_cannot_be_a_member(tmp_path):
    manifest = _write_composite(tmp_path)
    nested = {**manifest, "profile_id": "outer"}
    nested["members"] = [
        {"family": "command-injection", "profile_id": "composite-test", "profile": "composite.json"}
    ]
    nested["files"] = {
        "composite.json": _sha((tmp_path / "composite.json").read_bytes()),
        "composition.md": manifest["files"]["composition.md"],
    }
    (tmp_path / "outer.json").write_text(json.dumps(nested), encoding="utf-8")
    with pytest.raises(ProfileError, match="Unknown profile kind: 'composite'"):
        load_composite_profile(tmp_path, "outer.json")
    with pytest.raises(ProfileError, match="Unknown profile kind"):
        load_member_profile(tmp_path, "composite.json")


def test_the_repository_composite_profile_loads_with_its_pinned_members():
    profile = load_any_profile(ROOT, MANIFEST)
    assert isinstance(profile, CompositeProfile)
    assert (profile.profile_id, profile.composition) == ("multi-cwe-v0.1", COMPOSITION_VERSION)
    assert [(family, member.profile_id) for family, member in profile.members] == [
        ("command-injection", "command-injection-v0.3"),
        ("path-traversal", "path-traversal-v0.2"),
    ]
    # The members are byte for byte the profiles a single-profile scan uses.
    for _, member in profile.members:
        alone = load_any_profile(ROOT, f"profiles/{member.profile_id}/profile.json")
        assert member.manifest_sha256 == alone.manifest_sha256
    assert set(profile.configs) == {"javascript", "python"}
