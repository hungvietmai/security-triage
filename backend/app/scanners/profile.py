"""Hash-verified scan profile: the exact rules, rule claims and policy a scan may use.

A manifest (profiles/<id>/profile.json) names files by repository-relative path and pins
each by SHA-256. It points at the research files themselves rather than copies, so the
worker and the experiments read one source. Nothing is returned unless every pin matches.

Two kinds exist. A priority profile (no "kind") runs Semgrep and CodeQL and ranks units with
a priority policy. A "safety-evidence" profile runs a baseline query and the same query with
safety-evidence barriers from one pinned pack; the evidence query's alerts rank the baseline's.
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
    # Pinned rule path -> the rule ID its YAML defines (the worker cannot parse YAML).
    semgrep_rule_ids: dict[str, str]
    sink_locators: dict[str, Path]
    policy: dict[str, Any]
    # The source YAML's hash: what the policy specification requires assessments to record.
    policy_sha256: str
    specification_sha256: str
    rule_claims: dict[str, Any]
    rule_claims_sha256: str


@dataclass(frozen=True, slots=True)
class EvidenceProfile:
    profile_id: str
    manifest_sha256: str
    root: Path
    configs: dict[str, dict[str, Any]]
    # Directory holding qlpack.yml and the configured queries, under `root`.
    query_pack: Path
    baseline_rule: str
    evidence_rule: str
    policy_id: str
    policy_version: str
    # Hash of the evidence library: what assessments record as their policy.
    policy_sha256: str
    specification_sha256: str


AnyProfile = ScanProfile | EvidenceProfile
EVIDENCE_KIND = "safety-evidence"


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


def _verified(root: Path, manifest: str) -> tuple[bytes, dict[str, Any], dict[str, bytes]]:
    """The manifest bytes, its parsed JSON and every pinned file, all hashes checked."""
    manifest_bytes = _read(root, manifest)
    raw = json.loads(manifest_bytes)
    pins: dict[str, str] = raw["files"]
    files = {relative: _read(root, relative) for relative in pins}
    for relative, data in files.items():
        if _sha256(data) != pins[relative]:
            raise ProfileError(f"Profile hash mismatch: {relative}")
    return manifest_bytes, raw, files


def _pinned(files: dict[str, bytes], relative: str) -> bytes:
    if relative not in files:
        raise ProfileError(f"Profile does not pin {relative}")
    return files[relative]


def load_any_profile(root: Path, manifest: str) -> AnyProfile:
    """Load a profile of either kind; its "kind" field selects the loader."""
    try:
        kind = json.loads(_read(root.resolve(), manifest)).get("kind")
    except (AttributeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"Malformed scan profile: {exc!r}") from exc
    if kind == EVIDENCE_KIND:
        return load_evidence_profile(root, manifest)
    if kind is not None:
        raise ProfileError(f"Unknown profile kind: {kind!r}")
    return load_profile(root, manifest)


def load_evidence_profile(root: Path, manifest: str) -> EvidenceProfile:
    """Verify every pinned file, including each configured query, then return the profile."""
    root = root.resolve()
    try:
        manifest_bytes, raw, files = _verified(root, manifest)
        if raw.get("kind") != EVIDENCE_KIND:
            raise ProfileError("Not a safety-evidence profile")
        pack = raw["query_pack"]
        _pinned(files, f"{pack}/qlpack.yml")
        configs = {
            language: json.loads(_pinned(files, entry["config"]))
            for language, entry in raw["languages"].items()
        }
        for config in configs.values():
            if config["semgrep_rules"] or config["scanners"] != ["codeql"]:
                raise ProfileError("A safety-evidence profile runs CodeQL only")
            for query, sha256 in config["codeql_query_sha256"].items():
                if _sha256(_pinned(files, f"{pack}/{query}")) != sha256:
                    raise ProfileError(f"Config and profile pin {query} differently")
        policy = raw["policy"]
        return EvidenceProfile(
            profile_id=raw["profile_id"],
            manifest_sha256=_sha256(manifest_bytes),
            root=root,
            configs=configs,
            query_pack=root / pack,
            baseline_rule=raw["baseline_rule"],
            evidence_rule=raw["evidence_rule"],
            policy_id=policy["id"],
            policy_version=policy["version"],
            policy_sha256=_sha256(_pinned(files, policy["source"])),
            specification_sha256=_sha256(_pinned(files, raw["specification"])),
        )
    except (KeyError, TypeError, AttributeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"Malformed scan profile: {exc!r}") from exc


def load_profile(root: Path, manifest: str) -> ScanProfile:
    """Verify every pinned file under `root`, then return the parsed profile."""
    root = root.resolve()
    try:
        manifest_bytes, raw, files = _verified(root, manifest)

        def pinned(relative: str) -> bytes:
            return _pinned(files, relative)

        configs = {
            language: json.loads(pinned(entry["config"]))
            for language, entry in raw["languages"].items()
        }
        for config in configs.values():
            for rule in config["semgrep_rules"]:
                # Rules are staged from pinned local bytes; a scan never fetches a rule.
                pinned(rule["path"])
                if raw["files"][rule["path"]] != rule["sha256"]:
                    raise ProfileError(f"Config and profile pin {rule['path']} differently")
                if not isinstance(raw["semgrep_rule_ids"].get(rule["path"]), str):
                    raise ProfileError(f"Profile names no rule ID for {rule['path']}")
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
            semgrep_rule_ids=dict(raw["semgrep_rule_ids"]),
            sink_locators=locators,
            policy=json.loads(pinned(policy["compiled"])),
            policy_sha256=_sha256(pinned(policy["source"])),
            specification_sha256=_sha256(pinned(raw["specification"])),
            rule_claims=json.loads(pinned(raw["rule_claims"])),
            rule_claims_sha256=_sha256(pinned(raw["rule_claims"])),
        )
    except (KeyError, TypeError, AttributeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"Malformed scan profile: {exc!r}") from exc
