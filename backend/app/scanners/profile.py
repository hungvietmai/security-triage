"""Hash-verified scan profile: the exact rules, rule claims and policy a scan may use.

A manifest (profiles/<id>/profile.json) names files by repository-relative path and pins
each by SHA-256. It points at the research files themselves rather than copies, so the
worker and the experiments read one source. Nothing is returned unless every pin matches.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ProfileError(ValueError):
    """The profile is malformed, incomplete, or a pinned file does not match its hash."""


@dataclass(frozen=True, slots=True)
class ScanProfile:
    profile_id: str
    manifest_sha256: str
    root: Path
    configs: dict[str, dict[str, Any]]
    sink_locators: dict[str, Path]
    policy: dict[str, Any]
    # The source YAML's hash: what the policy specification requires assessments to record.
    policy_sha256: str
    specification_sha256: str
    rule_claims: dict[str, Any]
    rule_claims_sha256: str


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read(root: Path, relative: str) -> bytes:
    path = (root / relative).resolve()
    if Path(relative).is_absolute() or not path.is_relative_to(root):
        raise ProfileError(f"Profile path escapes its root: {relative}")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ProfileError(f"Profile file unreadable: {relative}") from exc


def load_profile(root: Path, manifest: str) -> ScanProfile:
    """Verify every pinned file under `root`, then return the parsed profile."""
    root = root.resolve()
    manifest_bytes = _read(root, manifest)
    try:
        raw = json.loads(manifest_bytes)
        pins: dict[str, str] = raw["files"]
        files = {relative: _read(root, relative) for relative in pins}
        for relative, data in files.items():
            if _sha256(data) != pins[relative]:
                raise ProfileError(f"Profile hash mismatch: {relative}")

        def pinned(relative: str) -> bytes:
            if relative not in files:
                raise ProfileError(f"Profile does not pin {relative}")
            return files[relative]

        configs = {
            language: json.loads(pinned(entry["config"]))
            for language, entry in raw["languages"].items()
        }
        for config in configs.values():
            for rule in config["semgrep_rules"]:
                # Rules are staged from pinned local bytes; a scan never fetches a rule.
                pinned(rule["path"])
                if pins[rule["path"]] != rule["sha256"]:
                    raise ProfileError(f"Config and profile pin {rule['path']} differently")
        locators: dict[str, Path] = {}
        for language, entry in raw["languages"].items():
            if "sink_locator" in entry:
                pinned(entry["sink_locator"])
                locators[language] = root / entry["sink_locator"]
        policy = raw["policy"]
        return ScanProfile(
            profile_id=raw["profile_id"],
            manifest_sha256=_sha256(manifest_bytes),
            root=root,
            configs=configs,
            sink_locators=locators,
            policy=json.loads(pinned(policy["compiled"])),
            policy_sha256=_sha256(pinned(policy["source"])),
            specification_sha256=_sha256(pinned(raw["specification"])),
            rule_claims=json.loads(pinned(raw["rule_claims"])),
            rule_claims_sha256=_sha256(pinned(raw["rule_claims"])),
        )
    except (KeyError, TypeError, AttributeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"Malformed scan profile: {exc!r}") from exc
