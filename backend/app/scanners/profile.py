"""Hash-verified scan profile: the exact rules, rule claims and policy a scan may use.

A manifest (profiles/<id>/profile.json) names files by repository-relative path and pins
each by SHA-256. It points at the research files themselves rather than copies, so the
worker and the experiments read one source. Nothing is returned unless every pin matches.

Two kinds exist. A priority profile (no "kind") runs Semgrep and CodeQL, optionally with the
screening tools Bandit and ESLint, and ranks units with a priority policy. A "safety-evidence"
profile runs a baseline query and the same query with safety-evidence barriers from one pinned
pack; the evidence query's alerts rank the baseline's.

A third kind, "composite", runs no rules of its own: it pins the manifests of member profiles,
one per analysis family, that are scanned together on one tool run. Each member stays the
profile it is, with its own pinned rules, policy and filter conditions.

A "detection" profile pins queries of the installed standard CodeQL pack by hash and names the
CWEs each of their rules is mapped to. It has no evidence query and no filter condition: every
alert is kept for review. It runs as a member of a composite profile, on the database the
composite's first member created.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.scanners.semgrep import TARGET_SELECTIONS


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


@dataclass(frozen=True, slots=True)
class DetectionProfile:
    """Detect and keep: pinned queries of the standard CodeQL pack, no evidence, no filter."""

    profile_id: str
    manifest_sha256: str
    root: Path
    configs: dict[str, dict[str, Any]]
    # Language -> rule ID -> the CWEs the pinned rule is mapped to; a rule may map to several.
    rules: dict[str, dict[str, list[str]]]
    # The one tier every unit of this profile gets; the profile has no ranking policy.
    priority: str
    policy_id: str
    policy_version: str
    # Hash of the specification: what assessments record as their policy.
    policy_sha256: str
    specification_sha256: str


AnyProfile = ScanProfile | EvidenceProfile | DetectionProfile


@dataclass(frozen=True, slots=True)
class CompositeProfile:
    """Member profiles scanned together; `members` is (analysis family, profile), in order."""

    profile_id: str
    manifest_sha256: str
    root: Path
    members: tuple[tuple[str, AnyProfile], ...]
    # Names how members are combined; recorded with every scan (see workflows/scans/families).
    composition: str
    specification_sha256: str

    @property
    def configs(self) -> dict[str, dict[str, Any]]:
        """Language configs of the member that runs the scanners: the languages a scan covers."""
        return self.members[0][1].configs


LoadedProfile = AnyProfile | CompositeProfile
# Scanners a priority profile's language config may add to Semgrep and CodeQL.
SCREENING_TOOLS = ("bandit", "eslint")
EVIDENCE_KIND = "safety-evidence"
DETECTION_KIND = "detection"
COMPOSITE_KIND = "composite"
# Tiers a detection profile may give its units.
DETECTION_PRIORITIES = ("P1", "P2", "U", "P3", "P4")


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


def _kind(root: Path, manifest: str) -> object:
    try:
        return json.loads(_read(root.resolve(), manifest)).get("kind")
    except (AttributeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"Malformed scan profile: {exc!r}") from exc


def load_member_profile(root: Path, manifest: str) -> AnyProfile:
    """Load a profile that scans by itself; its "kind" field selects the loader."""
    kind = _kind(root, manifest)
    if kind == EVIDENCE_KIND:
        return load_evidence_profile(root, manifest)
    if kind == DETECTION_KIND:
        return load_detection_profile(root, manifest)
    if kind is not None:
        raise ProfileError(f"Unknown profile kind: {kind!r}")
    return load_profile(root, manifest)


def load_any_profile(root: Path, manifest: str) -> LoadedProfile:
    """Load a profile of any kind; its "kind" field selects the loader."""
    if _kind(root, manifest) == COMPOSITE_KIND:
        return load_composite_profile(root, manifest)
    return load_member_profile(root, manifest)


def load_composite_profile(root: Path, manifest: str) -> CompositeProfile:
    """Verify the pinned member manifests, then load every member with its own loader.

    The composite pins each member's manifest by hash and the member's loader verifies what
    that manifest pins, so a scan uses exactly the bytes the member profile uses alone. The
    first member runs the scanners; a member cannot itself be a composite.
    """
    root = root.resolve()
    try:
        manifest_bytes, raw, files = _verified(root, manifest)
        if raw.get("kind") != COMPOSITE_KIND or raw.get("schema") != 2:
            raise ProfileError("Not a composite profile of schema 2")
        entries = raw["members"]
        if not isinstance(entries, list) or not entries:
            raise ProfileError("A composite profile needs at least one member")
        members: list[tuple[str, AnyProfile]] = []
        for entry in entries:
            family, path = entry["family"], entry["profile"]
            if not isinstance(family, str) or not family or not isinstance(path, str):
                raise ProfileError("A member needs an analysis family and a profile manifest")
            _pinned(files, path)
            member = load_member_profile(root, path)
            if entry["profile_id"] != member.profile_id:
                raise ProfileError(f"Member {path} is not profile {entry['profile_id']}")
            members.append((family, member))
        families = [family for family, _ in members]
        if len(set(families)) != len(families):
            raise ProfileError("A composite profile takes one member per analysis family")
        composition = raw["composition"]
        if not isinstance(composition, str) or not composition:
            raise ProfileError("A composite profile names its composition version")
        return CompositeProfile(
            profile_id=raw["profile_id"],
            manifest_sha256=_sha256(manifest_bytes),
            root=root,
            members=tuple(members),
            composition=composition,
            specification_sha256=_sha256(_pinned(files, raw["specification"])),
        )
    except (KeyError, TypeError, AttributeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"Malformed scan profile: {exc!r}") from exc


def load_detection_profile(root: Path, manifest: str) -> DetectionProfile:
    """Verify every pinned file, then return a profile that detects and keeps.

    The queries belong to the installed standard pack, not to the repository, so their bytes
    are checked against the configured hashes when they run (`run_codeql_evidence`).
    """
    root = root.resolve()
    try:
        manifest_bytes, raw, files = _verified(root, manifest)
        if raw.get("kind") != DETECTION_KIND:
            raise ProfileError("Not a detection profile")
        configs = {
            language: json.loads(_pinned(files, entry["config"]))
            for language, entry in raw["languages"].items()
        }
        rules: dict[str, dict[str, list[str]]] = {}
        for language, config in configs.items():
            if config["semgrep_rules"] or config["scanners"] != ["codeql"]:
                raise ProfileError("A detection profile runs CodeQL only")
            if not config["codeql_queries"] or set(config["codeql_queries"]) != set(
                config["codeql_query_sha256"]
            ):
                raise ProfileError("Detection queries and their hashes differ")
            mapped = raw["rules"].get(language)
            if not isinstance(mapped, dict) or not mapped:
                raise ProfileError(f"A detection profile names no rules for {language}")
            for rule, cwes in mapped.items():
                if (
                    not isinstance(cwes, list)
                    or not cwes
                    or not all(
                        isinstance(cwe, str) and cwe.startswith("CWE-") and cwe[4:].isdigit()
                        for cwe in cwes
                    )
                ):
                    raise ProfileError(f"Rule {rule} names no mapped CWE")
            rules[language] = {rule: list(cwes) for rule, cwes in mapped.items()}
        if set(raw["rules"]) != set(configs):
            raise ProfileError("Rules and language configs name different languages")
        priority = raw["priority"]
        if priority not in DETECTION_PRIORITIES:
            raise ProfileError(f"Unknown priority tier: {priority!r}")
        policy = raw["policy"]
        return DetectionProfile(
            profile_id=raw["profile_id"],
            manifest_sha256=_sha256(manifest_bytes),
            root=root,
            configs=configs,
            rules=rules,
            priority=priority,
            policy_id=policy["id"],
            policy_version=policy["version"],
            policy_sha256=_sha256(_pinned(files, policy["source"])),
            specification_sha256=_sha256(_pinned(files, raw["specification"])),
        )
    except (KeyError, TypeError, AttributeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"Malformed scan profile: {exc!r}") from exc


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
            for tool in SCREENING_TOOLS:
                if (tool in config) != (tool in config.get("scanners", ())):
                    raise ProfileError(f"Config must both list and configure {tool}")
                if tool not in config:
                    continue
                entry = config[tool]
                if not entry["version"] or not entry["rules"]:
                    raise ProfileError(f"Config names no version or rules for {tool}")
                # The tool's configuration, and for ESLint the lockfile its plugins come from.
                for name in ("config", "lockfile") if tool == "eslint" else ("config",):
                    pinned(entry[name]["path"])
                    if raw["files"][entry[name]["path"]] != entry[name]["sha256"]:
                        raise ProfileError(
                            f"Config and profile pin {entry[name]['path']} differently"
                        )
            evidence = config.get("adjudication", {}).get("codeql_evidence")
            if evidence is not None:
                # The evidence pack's library and lock decide what its queries mean.
                pack = evidence["query_pack"]
                for name in evidence["pack_files"]:
                    pinned(f"{pack}/{name}")
                for query, sha256 in evidence["query_sha256"].items():
                    if _sha256(pinned(f"{pack}/{query}")) != sha256:
                        raise ProfileError(f"Config and profile pin {query} differently")
                if set(evidence["queries"]) != set(evidence["query_sha256"]):
                    raise ProfileError("Evidence queries and their hashes differ")
            selection = config.get("semgrep_target_selection")
            if selection is not None and selection not in TARGET_SELECTIONS:
                raise ProfileError(f"Unknown Semgrep target selection: {selection}")
            semgrep_evidence = config.get("adjudication", {}).get("semgrep_evidence")
            if semgrep_evidence is not None:
                rules = semgrep_evidence["rules"]
                pinned(rules["path"])
                if raw["files"][rules["path"]] != rules["sha256"]:
                    raise ProfileError(f"Config and profile pin {rules['path']} differently")
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
