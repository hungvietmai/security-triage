#!/usr/bin/env python3
"""
Audit flagged SecBench.js/PyVul inventory rows before any scanner run.

Checks:
- SecBench.js GHSA source_code_location vs fix_commit repository.
- GHSA package identity and first_patched_version.
- npm existence of every vulnerable/fixed version.
- PyVul fixing-commit parent (exactly one GitHub API request per PyVul row).

The script mutates only provenance/source fields and split/exclusion metadata.
It never runs Semgrep or CodeQL.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

GHSA_RE = re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", re.I)
CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$", re.I)
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$", re.I)

DEFAULT_INVENTORY = Path("experiments/inventory/pair-inventory.csv")
DEFAULT_REPORT = Path("experiments/inventory/FLAGGED_REVIEW_2026-10-05.md")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    p.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    p.add_argument("--github-token", default=os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN"))
    return p.parse_args()


def get_json(url: str, token: str | None = None) -> Any:
    headers = {
        "Accept": "application/vnd.github+json" if url.startswith("https://api.github.com/") else "application/json",
        "User-Agent": "security-triage-inventory-audit/1.0",
    }
    if url.startswith("https://api.github.com/"):
        if not token:
            raise RuntimeError("GITHUB_TOKEN or GH_TOKEN is required for GitHub API calls")
        headers["Authorization"] = f"Bearer {token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code} for {url}: {body[:800]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Request failed for {url}: {exc}") from exc


def split_pipe(value: str) -> list[str]:
    return [x for x in value.split("|") if x]


def join_pipe(values: list[str]) -> str:
    return "|".join(dict.fromkeys(x for x in values if x))


def normalize_repo_from_url(url: str | None) -> str | None:
    if not url:
        return None
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return None
    if parsed.netloc.lower() != "github.com":
        return None
    parts = [x for x in parsed.path.strip("/").split("/") if x]
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    return f"{owner}/{repo}".lower()


def package_from_row(row: dict[str, str]) -> str:
    return row["vulnerable_source.package_name"].strip()


def normalize_exact_version(value: str) -> str:
    value = value.strip()
    if value.startswith("="):
        return value[1:].strip()
    return value


def ghsa_ids(row: dict[str, str]) -> list[str]:
    ids: list[str] = []
    for value in split_pipe(row.get("cwe_provenance", "")) + split_pipe(row.get("reference_provenance", "")):
        ids.extend(m.upper() for m in GHSA_RE.findall(value))
    return list(dict.fromkeys(ids))


def fetch_ghsa_records(row: dict[str, str], token: str) -> list[dict[str, Any]]:
    ids = ghsa_ids(row)
    records: list[dict[str, Any]] = []
    if ids:
        for ghsa_id in ids:
            records.append(get_json(f"https://api.github.com/advisories/{ghsa_id}", token))
        return records

    cve = row["vulnerability_id"].strip().upper()
    if not CVE_RE.fullmatch(cve):
        return []
    query = urllib.parse.urlencode({"cve_id": cve, "per_page": 100})
    payload = get_json(f"https://api.github.com/advisories?{query}", token)
    if not isinstance(payload, list):
        raise RuntimeError(f"{row['pair_id']}: unexpected advisory-list response")
    return [x for x in payload if isinstance(x, dict)]


def matching_ghsa_package_records(records: list[dict[str, Any]], package: str) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    matches: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for record in records:
        for vuln in record.get("vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            pkg = vuln.get("package")
            if not isinstance(pkg, dict):
                continue
            ecosystem = str(pkg.get("ecosystem") or "").lower()
            name = str(pkg.get("name") or "")
            if ecosystem == "npm" and name == package:
                matches.append((record, vuln))
    return matches


def first_patched_versions(matches: list[tuple[dict[str, Any], dict[str, Any]]]) -> list[str]:
    values: list[str] = []
    for _, vuln in matches:
        value = vuln.get("first_patched_version")
        if isinstance(value, str) and value.strip():
            values.append(normalize_exact_version(value))
    return list(dict.fromkeys(values))


def source_locations(records: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    for record in records:
        value = record.get("source_code_location")
        if isinstance(value, str) and value.strip():
            values.append(value.strip())
    return list(dict.fromkeys(values))


def exclude(row: dict[str, str], reason: str) -> None:
    row["split"] = "excluded"
    old = row.get("exclusion_reason", "").strip()
    if old and reason not in old:
        row["exclusion_reason"] = f"{old}; {reason}"
    elif not old:
        row["exclusion_reason"] = reason


def set_fixed_version(row: dict[str, str], version: str) -> None:
    row["fixed_ref"] = version
    row["fixed_source.source_kind"] = "npm_tarball"
    row["fixed_source.package_name"] = package_from_row(row)
    row["fixed_source.package_version"] = version
    row["fixed_source.repository"] = ""
    row["fixed_source.commit"] = ""
    row["fixed_source.source_reference"] = f"npm:{package_from_row(row)}@{version}"


def append_provenance(row: dict[str, str], value: str) -> None:
    values = split_pipe(row.get("reference_provenance", ""))
    if value not in values:
        values.append(value)
    row["reference_provenance"] = join_pipe(values)


def npm_versions(package: str, cache: dict[str, set[str]]) -> set[str]:
    if package not in cache:
        encoded = urllib.parse.quote(package, safe="")
        payload = get_json(f"https://registry.npmjs.org/{encoded}")
        versions = payload.get("versions") if isinstance(payload, dict) else None
        if not isinstance(versions, dict):
            raise RuntimeError(f"npm registry returned no versions map for {package}")
        cache[package] = set(versions)
    return cache[package]


def audit_secbench(
    row: dict[str, str],
    *,
    token: str,
    npm_cache: dict[str, set[str]],
) -> dict[str, Any]:
    before = {
        "fix_commit": row["fix_commit"],
        "fixed_ref": row["fixed_ref"],
        "split": row["split"],
        "exclusion_reason": row["exclusion_reason"],
    }
    package = package_from_row(row)
    versions = npm_versions(package, npm_cache)
    vulnerable = normalize_exact_version(row["vulnerable_ref"])
    fixed = normalize_exact_version(row["fixed_ref"]) if row["fixed_ref"].strip() else ""

    records = fetch_ghsa_records(row, token)
    matches = matching_ghsa_package_records(records, package)
    locations = source_locations(records)
    source_repos = sorted({r for r in (normalize_repo_from_url(x) for x in locations) if r})

    fix_repo = normalize_repo_from_url(row["fix_commit"])
    mismatch = bool(fix_repo and source_repos and fix_repo not in source_repos)
    package_mismatch = bool(records and not matches)
    actions: list[str] = []
    flags: list[str] = []

    if mismatch:
        flags.append("fix_commit_repo_mismatch")

    if package_mismatch:
        flags.append("ghsa_package_mismatch")
        exclude(
            row,
            "GHSA advisory package does not match the SecBench npm package; provenance is not reliable for primary evaluation",
        )
        actions.append("excluded_ghsa_package_mismatch")

    # Preserve source_code_location in provenance whether or not a bad fix reference exists.
    for location in locations:
        append_provenance(row, f"GHSA_SOURCE:{location}")

    if mismatch and not package_mismatch:
        old = row["fix_commit"]
        row["fix_commit"] = ""
        actions.append(f"removed_mismatched_fix_commit:{old}")

    if vulnerable not in versions:
        flags.append("vulnerable_version_missing_npm")
        exclude(row, f"vulnerable npm version {vulnerable!r} does not exist in the npm registry")
        actions.append("excluded_missing_vulnerable_version")

    patched = first_patched_versions(matches)

    same_version = bool(fixed and fixed == vulnerable)
    if same_version:
        flags.append("fixed_equals_vulnerable")
        usable = [v for v in patched if v != vulnerable and v in versions]
        if len(usable) == 1:
            set_fixed_version(row, usable[0])
            fixed = usable[0]
            actions.append(f"repaired_fixed_version_from_ghsa:{usable[0]}")
        else:
            exclude(
                row,
                "fixed version equals vulnerable version and GHSA does not provide one unique existing first_patched_version",
            )
            actions.append("excluded_unresolved_same_version")

    # Normalize leading '=' only if it names a real exact npm version.
    if fixed and fixed != row["fixed_ref"] and fixed in versions:
        set_fixed_version(row, fixed)
        actions.append(f"normalized_fixed_version:{fixed}")

    if fixed:
        if fixed not in versions:
            flags.append("fixed_version_missing_npm")
            usable = [v for v in patched if v in versions and v != vulnerable]
            if len(usable) == 1:
                set_fixed_version(row, usable[0])
                fixed = usable[0]
                actions.append(f"repaired_missing_fixed_version_from_ghsa:{usable[0]}")
            else:
                exclude(row, f"fixed npm version {fixed!r} does not exist and no unique existing GHSA first_patched_version is available")
                actions.append("excluded_missing_fixed_version")
    else:
        flags.append("fixed_version_absent")
        # Existing source-policy exclusions remain exclusions. If GHSA has one clear
        # patched npm version, repair it because this audit explicitly authorizes
        # first_patched_version as the source of truth.
        usable = [v for v in patched if v in versions and v != vulnerable]
        if len(usable) == 1 and not package_mismatch:
            set_fixed_version(row, usable[0])
            row["split"] = "unassigned"
            row["exclusion_reason"] = ""
            fixed = usable[0]
            actions.append(f"recovered_fixed_version_from_ghsa:{usable[0]}")

    return {
        "pair_id": row["pair_id"],
        "package": package,
        "vulnerability_id": row["vulnerability_id"],
        "flags": flags,
        "actions": actions,
        "ghsa_ids": [str(r.get("ghsa_id") or "") for r in records],
        "ghsa_source_code_location": locations,
        "ghsa_first_patched_versions": patched,
        "npm_vulnerable_exists": vulnerable in versions,
        "npm_fixed_exists": bool(fixed and fixed in versions),
        "before": before,
        "after": {
            "fix_commit": row["fix_commit"],
            "fixed_ref": row["fixed_ref"],
            "split": row["split"],
            "exclusion_reason": row["exclusion_reason"],
        },
    }


def audit_pyvul(row: dict[str, str], *, token: str) -> dict[str, Any]:
    fix = row["fix_commit"].strip()
    repo = row["repository"].strip()
    if not COMMIT_RE.fullmatch(fix):
        raise RuntimeError(f"{row['pair_id']}: invalid PyVul fix commit {fix!r}")

    # Exactly one GitHub commit API call for this PyVul row.
    payload = get_json(f"https://api.github.com/repos/{repo}/commits/{fix}", token)
    parents = payload.get("parents") if isinstance(payload, dict) else None
    if not isinstance(parents, list):
        raise RuntimeError(f"{row['pair_id']}: missing parents array from GitHub API")

    old_parent = row["vulnerable_ref"]
    if not parents:
        row["vulnerable_ref"] = ""
        row["vulnerable_source.source_kind"] = ""
        row["vulnerable_source.repository"] = ""
        row["vulnerable_source.commit"] = ""
        row["vulnerable_source.source_reference"] = ""
        exclude(row, "PyVul fixing commit has no parent; vulnerable snapshot cannot be constructed by the parent-of-fix rule")
        new_parent = ""
        action = "excluded_no_parent"
    else:
        new_parent = str(parents[0].get("sha") or "")
        if not COMMIT_RE.fullmatch(new_parent):
            raise RuntimeError(f"{row['pair_id']}: invalid first-parent SHA {new_parent!r}")
        row["vulnerable_ref"] = new_parent
        row["vulnerable_source.source_kind"] = "github_tarball"
        row["vulnerable_source.repository"] = repo
        row["vulnerable_source.commit"] = new_parent
        row["vulnerable_source.source_reference"] = f"github:{repo}@{new_parent}"
        if row["split"] == "excluded" and "has no parent" in row["exclusion_reason"]:
            row["split"] = "unassigned"
            row["exclusion_reason"] = ""
        action = "confirmed_parent" if old_parent == new_parent else "updated_parent"

    return {
        "pair_id": row["pair_id"],
        "repository": repo,
        "fix_commit": fix,
        "parent_count": len(parents),
        "old_parent": old_parent,
        "new_parent": new_parent,
        "action": action,
    }


def markdown_report(sec_results: list[dict[str, Any]], py_results: list[dict[str, Any]]) -> str:
    mismatches = [x for x in sec_results if "fix_commit_repo_mismatch" in x["flags"]]
    same = [x for x in sec_results if "fixed_equals_vulnerable" in x["flags"]]
    missing_v = [x for x in sec_results if "vulnerable_version_missing_npm" in x["flags"]]
    missing_f = [x for x in sec_results if "fixed_version_missing_npm" in x["flags"]]
    excluded = [x for x in sec_results if x["after"]["split"] == "excluded"]
    action_counts = Counter(a for x in sec_results for a in x["actions"])

    lines = [
        "# Flagged inventory review — 2026-10-05",
        "",
        "This review was performed before any new Semgrep/CodeQL pair scan.",
        "",
        "## Summary",
        "",
        f"- SecBench.js rows checked against npm: **{len(sec_results)}**",
        f"- `fix_commit` repository mismatches vs GHSA `source_code_location`: **{len(mismatches)}**",
        f"- vulnerable/fixed version equality flags: **{len(same)}**",
        f"- missing vulnerable npm versions after normalization: **{len(missing_v)}**",
        f"- missing fixed npm versions before repair/exclusion: **{len(missing_f)}**",
        f"- SecBench.js rows excluded after review: **{len(excluded)}**",
        f"- PyVul fixing commits queried through GitHub API: **{len(py_results)}**",
        f"- PyVul rows with no parent: **{sum(x['parent_count'] == 0 for x in py_results)}**",
        "",
        "## SecBench.js flagged rows",
        "",
        "| pair_id | flags | action | GHSA source | fixed version after | status |",
        "|---|---|---|---|---|---|",
    ]
    for x in sec_results:
        if not x["flags"] and not x["actions"]:
            continue
        source = "<br>".join(x["ghsa_source_code_location"]) or "—"
        lines.append(
            f"| {x['pair_id']} | {', '.join(x['flags']) or '—'} | "
            f"{', '.join(x['actions']) or 'no change'} | {source} | "
            f"{x['after']['fixed_ref'] or '—'} | {x['after']['split']} |"
        )

    lines += [
        "",
        "## Action counts",
        "",
    ]
    for action, count in sorted(action_counts.items()):
        lines.append(f"- `{action}`: {count}")

    lines += [
        "",
        "## PyVul parent verification",
        "",
        "| pair_id | fix commit | first parent | parent count | action |",
        "|---|---|---|---:|---|",
    ]
    for x in py_results:
        lines.append(
            f"| {x['pair_id']} | `{x['fix_commit']}` | "
            f"`{x['new_parent'] or 'none'}` | {x['parent_count']} | {x['action']} |"
        )

    lines += [
        "",
        "## Audit rules",
        "",
        "- GHSA package identity is checked before using `first_patched_version`.",
        "- A mismatched SecBench.js `fix_commit` is removed when the GHSA package matches; the GHSA source repository is retained in provenance.",
        "- If the GHSA package itself does not match the npm package, the row is excluded rather than repaired by inference.",
        "- npm versions are checked against the registry metadata for the exact package.",
        "- PyVul vulnerable snapshots use the first parent returned by one GitHub commit API request per fixing commit.",
        "- No scanner result was used by this review.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    if not args.github_token:
        print("GITHUB_TOKEN or GH_TOKEN is required", file=sys.stderr)
        return 2

    with args.inventory.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames:
            raise RuntimeError("inventory header missing")
        fieldnames = reader.fieldnames
        rows = list(reader)

    npm_cache: dict[str, set[str]] = {}
    sec_results: list[dict[str, Any]] = []
    py_results: list[dict[str, Any]] = []

    for row in rows:
        if row["dataset"] == "SecBench.js":
            sec_results.append(audit_secbench(row, token=args.github_token, npm_cache=npm_cache))
        elif row["dataset"] == "PyVul":
            py_results.append(audit_pyvul(row, token=args.github_token))

    if len(py_results) != 36:
        raise RuntimeError(f"expected 36 PyVul rows, got {len(py_results)}")

    with args.inventory.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    args.report.write_text(markdown_report(sec_results, py_results), encoding="utf-8")

    print(json.dumps({
        "secbench_rows": len(sec_results),
        "pyvul_commit_api_calls": len(py_results),
        "fix_commit_repo_mismatches": sum("fix_commit_repo_mismatch" in x["flags"] for x in sec_results),
        "same_version_flags": sum("fixed_equals_vulnerable" in x["flags"] for x in sec_results),
        "secbench_excluded_after_review": sum(x["after"]["split"] == "excluded" for x in sec_results),
        "pyvul_no_parent": sum(x["parent_count"] == 0 for x in py_results),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
