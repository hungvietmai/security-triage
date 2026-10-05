#!/usr/bin/env python3
"""
Fill SecBench.js CWE fields in experiments/inventory/pair-inventory.csv.

Resolution order:
1. GitHub Security Advisory (explicit GHSA link in pinned SecBench metadata, or
   GHSA lookup by CVE when no explicit link is available).
2. NVD only when no GHSA source provides a CWE.
3. cwe_unresolved when neither source yields one.

If authoritative records at the selected source level disagree, preserve all
reported CWE values and leave adjudicated_cwe as cwe_unresolved.

PyVul rows are left unchanged because their dataset CWE provenance is already
recorded from the pinned PyVul source.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Iterable

CWE_RE = re.compile(r"^CWE-[0-9]+$")
GHSA_RE = re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", re.I)
CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$", re.I)
BLOB_RE = re.compile(
    r"^https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/blob/"
    r"(?P<ref>[^/]+)/(?P<path>.+)$"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--inventory",
        type=Path,
        default=Path("experiments/inventory/pair-inventory.csv"),
    )
    parser.add_argument(
        "--github-token",
        default=os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN"),
    )
    parser.add_argument("--nvd-api-key", default=os.getenv("NVD_API_KEY"))
    parser.add_argument("--nvd-delay", type=float, default=None)
    return parser.parse_args()


def request_json(
    url: str,
    *,
    github_token: str | None = None,
    nvd_api_key: str | None = None,
) -> object:
    headers = {
        "Accept": "application/json",
        "User-Agent": "security-triage-cwe-curation/1.0",
    }
    if url.startswith("https://api.github.com/"):
        if not github_token:
            raise RuntimeError("GITHUB_TOKEN or GH_TOKEN is required")
        headers["Authorization"] = f"Bearer {github_token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    if url.startswith("https://services.nvd.nist.gov/") and nvd_api_key:
        headers["apiKey"] = nvd_api_key

    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code} for {url}: {body[:500]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Request failed for {url}: {exc}") from exc


def fetch_text(url: str) -> str:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "security-triage-cwe-curation/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code} for {url}: {body[:500]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Request failed for {url}: {exc}") from exc


def split_pipe(value: str) -> list[str]:
    return [part for part in value.split("|") if part]


def join_pipe(values: Iterable[str]) -> str:
    return "|".join(dict.fromkeys(v for v in values if v))


def normalize_cwes(values: Iterable[str]) -> list[str]:
    return sorted({value.upper() for value in values if CWE_RE.fullmatch(value.upper())})


def secbench_metadata(row: dict[str, str]) -> dict:
    refs = split_pipe(row["reference_provenance"])
    blob_url = next(
        (
            ref
            for ref in refs
            if ref.startswith("https://github.com/cristianstaicu/SecBench.js/blob/")
            and ref.endswith("/package.json")
        ),
        None,
    )
    if not blob_url:
        raise RuntimeError(f"{row['pair_id']}: pinned SecBench package.json reference missing")

    match = BLOB_RE.match(blob_url)
    if not match:
        raise RuntimeError(f"{row['pair_id']}: invalid GitHub blob URL: {blob_url}")

    raw_url = (
        "https://raw.githubusercontent.com/"
        f"{match.group('owner')}/{match.group('repo')}/{match.group('ref')}/"
        f"{match.group('path')}"
    )
    return json.loads(fetch_text(raw_url))


def ghsa_ids_from_metadata(metadata: dict) -> list[str]:
    values: list[str] = []
    links = metadata.get("links")
    if isinstance(links, dict):
        values.extend(str(value) for value in links.values() if value)
    link = metadata.get("link")
    if isinstance(link, dict):
        values.extend(str(value) for value in link.values() if value)

    ids: list[str] = []
    for value in values:
        ids.extend(match.upper() for match in GHSA_RE.findall(value))
    return list(dict.fromkeys(ids))


def cwes_from_ghsa_record(record: object) -> list[str]:
    if not isinstance(record, dict):
        return []
    values: list[str] = []
    for item in record.get("cwes") or []:
        if isinstance(item, dict):
            value = item.get("cwe_id")
            if isinstance(value, str):
                values.append(value)
        elif isinstance(item, str):
            values.append(item)
    return normalize_cwes(values)


def github_advisories_for_row(
    row: dict[str, str],
    metadata: dict,
    token: str,
) -> list[tuple[str, list[str]]]:
    ghsa_ids = ghsa_ids_from_metadata(metadata)
    records: list[tuple[str, list[str]]] = []

    if ghsa_ids:
        for ghsa_id in ghsa_ids:
            url = f"https://api.github.com/advisories/{ghsa_id}"
            record = request_json(url, github_token=token)
            records.append((url, cwes_from_ghsa_record(record)))
        return records

    vulnerability_id = row["vulnerability_id"].strip().upper()
    if not CVE_RE.fullmatch(vulnerability_id):
        return []

    query = urllib.parse.urlencode({"cve_id": vulnerability_id, "per_page": 100})
    url = f"https://api.github.com/advisories?{query}"
    payload = request_json(url, github_token=token)
    if not isinstance(payload, list):
        raise RuntimeError(f"{row['pair_id']}: unexpected GitHub advisory response")

    for record in payload:
        if not isinstance(record, dict):
            continue
        ghsa_id = record.get("ghsa_id")
        advisory_url = (
            f"https://api.github.com/advisories/{ghsa_id}"
            if isinstance(ghsa_id, str) and ghsa_id
            else url
        )
        records.append((advisory_url, cwes_from_ghsa_record(record)))
    return records


def nvd_cwes(
    cve_id: str,
    *,
    api_key: str | None,
    delay: float,
) -> tuple[str, list[str]]:
    if delay > 0:
        time.sleep(delay)
    query = urllib.parse.urlencode({"cveId": cve_id})
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{query}"
    payload = request_json(url, nvd_api_key=api_key)

    values: list[str] = []
    if isinstance(payload, dict):
        for wrapper in payload.get("vulnerabilities") or []:
            if not isinstance(wrapper, dict):
                continue
            cve = wrapper.get("cve")
            if not isinstance(cve, dict):
                continue
            for weakness in cve.get("weaknesses") or []:
                if not isinstance(weakness, dict):
                    continue
                for description in weakness.get("description") or []:
                    if not isinstance(description, dict):
                        continue
                    value = description.get("value")
                    if isinstance(value, str):
                        values.append(value)
    return url, normalize_cwes(values)


def resolve_row(
    row: dict[str, str],
    *,
    token: str,
    nvd_api_key: str | None,
    nvd_delay: float,
) -> tuple[list[str], str, list[str]]:
    metadata = secbench_metadata(row)
    ghsa_records = github_advisories_for_row(row, metadata, token)

    ghsa_nonempty = [(url, cwes) for url, cwes in ghsa_records if cwes]
    if ghsa_nonempty:
        all_cwes = normalize_cwes(
            cwe for _, cwes in ghsa_nonempty for cwe in cwes
        )
        source_sets = {tuple(cwes) for _, cwes in ghsa_nonempty}
        conflict = len(source_sets) > 1 or len(all_cwes) != 1
        provenance = [
            f"GHSA:{url}#{','.join(cwes)}" for url, cwes in ghsa_nonempty
        ]
        return (
            all_cwes,
            "cwe_unresolved" if conflict else all_cwes[0],
            provenance,
        )

    vulnerability_id = row["vulnerability_id"].strip().upper()
    if CVE_RE.fullmatch(vulnerability_id):
        nvd_url, nvd_values = nvd_cwes(
            vulnerability_id,
            api_key=nvd_api_key,
            delay=nvd_delay,
        )
        if nvd_values:
            return (
                nvd_values,
                nvd_values[0] if len(nvd_values) == 1 else "cwe_unresolved",
                [f"NVD:{nvd_url}#{','.join(nvd_values)}"],
            )

    return [], "cwe_unresolved", []


def main() -> int:
    args = parse_args()
    if not args.github_token:
        print("GITHUB_TOKEN or GH_TOKEN is required", file=sys.stderr)
        return 2

    nvd_delay = args.nvd_delay
    if nvd_delay is None:
        nvd_delay = 0.7 if args.nvd_api_key else 6.2

    with args.inventory.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        fieldnames = reader.fieldnames
        if not fieldnames:
            raise RuntimeError("Inventory has no CSV header")
        rows = list(reader)

    changed = 0
    summary: dict[str, int] = {}
    for row in rows:
        if row["dataset"] != "SecBench.js":
            continue

        reported, adjudicated, provenance = resolve_row(
            row,
            token=args.github_token,
            nvd_api_key=args.nvd_api_key,
            nvd_delay=nvd_delay,
        )
        new_values = {
            "reported_cwes": join_pipe(reported),
            "adjudicated_cwe": adjudicated,
            "cwe_provenance": join_pipe(provenance),
        }
        if any(row[key] != value for key, value in new_values.items()):
            row.update(new_values)
            changed += 1

        summary[adjudicated] = summary.get(adjudicated, 0) + 1

    with args.inventory.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    print(
        json.dumps(
            {
                "changed_rows": changed,
                "secbench_rows": sum(r["dataset"] == "SecBench.js" for r in rows),
                "adjudicated_counts": summary,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
