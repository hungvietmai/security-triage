"""A composite profile in the worker: its members, their families and the start-up check."""

import dataclasses

import pytest

from app.scanners.profile import CompositeProfile, ProfileError, load_any_profile
from app.workflows.scans.families import COMPOSITION_VERSION, members_of
from scripts import check_worker
from tests.scanners.test_profile import ROOT

MANIFEST = "profiles/multi-cwe-v0.1/profile.json"


def test_the_repository_composite_profile_pins_the_two_existing_profiles():
    profile = load_any_profile(ROOT, MANIFEST)
    assert isinstance(profile, CompositeProfile)
    assert (profile.profile_id, profile.composition) == ("multi-cwe-v0.1", COMPOSITION_VERSION)
    members = members_of(profile)
    assert [(member.family, member.profile.profile_id) for member in members] == [
        ("command-injection", "command-injection-v0.3"),
        ("path-traversal", "path-traversal-v0.2"),
    ]
    # The members are byte for byte the profiles a single-profile scan uses.
    for member in members:
        alone = load_any_profile(ROOT, f"profiles/{member.profile.profile_id}/profile.json")
        assert member.profile.manifest_sha256 == alone.manifest_sha256
    assert set(profile.configs) == {"javascript", "python"}


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (
            lambda p: dataclasses.replace(p, composition="family-composition-v9"),
            "Unknown composition",
        ),
        (
            lambda p: dataclasses.replace(
                p, members=(("sql-injection", p.members[0][1]), p.members[1])
            ),
            "is not a member of family 'sql-injection'",
        ),
        (
            # A profile declared for a family it does not belong to.
            lambda p: dataclasses.replace(
                p,
                members=(
                    ("path-traversal", p.members[0][1]),
                    ("command-injection", p.members[1][1]),
                ),
            ),
            "is not a member of family",
        ),
        (
            lambda p: dataclasses.replace(p, members=(p.members[1],)),
            "exactly one member that runs the scanners",
        ),
    ],
)
def test_a_composite_must_name_families_this_worker_handles(change, message):
    profile = load_any_profile(ROOT, MANIFEST)
    assert isinstance(profile, CompositeProfile)
    with pytest.raises(ValueError, match=message):
        members_of(change(profile))
    # The worker refuses to start with such a profile instead of failing a scan later.
    with pytest.raises(ProfileError, match=message):
        check_worker.member_profiles(change(profile))


def test_the_worker_check_verifies_the_members_of_a_composite_profile():
    calls: list[tuple[str, str]] = []

    def fake(binary, expected, output, tool, steps, /, *, working_directory, invoke_fn):
        calls.append((tool, expected))

    message = check_worker.check(ROOT, MANIFEST, tool_version_fn=fake)
    pins = check_worker.read_pins(ROOT / "tools/pins.env")
    # Every scanner a member uses is checked, although the composite lists none itself.
    assert calls == [
        ("semgrep", pins["SEMGREP_VERSION"]),
        ("codeql", pins["CODEQL_VERSION"]),
        ("bandit", pins["BANDIT_VERSION"]),
        ("eslint", pins["ESLINT_VERSION"]),
    ]
    assert message.startswith("Worker ready: profiles multi-cwe-v0.1 sha256=")
    profile = load_any_profile(ROOT, MANIFEST)
    with pytest.raises(ProfileError, match="differs from tools/pins.env"):
        for member in check_worker.member_profiles(profile):
            check_worker.check_pins(member, {**pins, "CODEQL_VERSION": "0.0.0"})
