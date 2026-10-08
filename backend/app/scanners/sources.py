"""Server-built downloads for user-named sources: npm package versions and GitHub commits.

Users name a source; they never supply a URL. Each URL is built here from validated
coordinates, must be HTTPS on port 443 to an allowlisted host, and is fetched without
following any redirect, so a request cannot be steered at another host (SSRF). The
hash-pinned research path (acquisition.acquire_source) is separate and unchanged.
"""

import base64
import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from email.message import Message
from typing import IO, Any, NoReturn

from app.scanners.acquisition import MAX_ARCHIVE

NPM_REGISTRY = "registry.npmjs.org"
GITHUB_CODELOAD = "codeload.github.com"
ALLOWED_HOSTS = frozenset({NPM_REGISTRY, GITHUB_CODELOAD})
MAX_METADATA = 5 * 1024 * 1024
TIMEOUT_SECONDS = 30  # applies to the connection and to every read

# npm package names (validate-npm-package-name, new-package rules): lowercase, URL-safe,
# optional @scope/, never starting with "." or "_"; at most 214 characters.
_NPM_NAME = re.compile(r"(?:@[a-z0-9~-][a-z0-9._~-]*/)?[a-z0-9~-][a-z0-9._~-]*")
# Full SemVer 2.0.0: an exact version, so no ranges, "latest" or other dist-tags.
_SEMVER = re.compile(
    r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*)?"
    r"(?:\+[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*)?"
)
_GITHUB_OWNER = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}")
_GITHUB_REPO = re.compile(r"[A-Za-z0-9._-]{1,100}")
_COMMIT = re.compile(r"[0-9a-f]{40}")

Fetch = Callable[[str, int], bytes]


class SourceError(ValueError):
    """The named source is invalid, unavailable or fails verification; retrying won't help."""


@dataclass(frozen=True, slots=True)
class FetchedArchive:
    data: bytes
    sha256: str
    artifact_url: str
    # publisher_verified: the registry's own sha512; tofu: trusted on first download.
    provenance_kind: str
    # The single top-level directory the archive must have; None when not fixed in advance.
    archive_root: str | None


def validate_npm(name: str, version: str) -> None:
    if len(name) > 214 or not _NPM_NAME.fullmatch(name):
        raise SourceError(f"Invalid npm package name: {name!r}")
    if not _SEMVER.fullmatch(version):
        raise SourceError(f"npm version must be an exact SemVer version: {version!r}")


def validate_github(owner: str, repo: str, commit: str) -> None:
    if not _GITHUB_OWNER.fullmatch(owner):
        raise SourceError(f"Invalid GitHub owner: {owner!r}")
    if not _GITHUB_REPO.fullmatch(repo) or repo in {".", ".."}:
        raise SourceError(f"Invalid GitHub repository: {repo!r}")
    if not _COMMIT.fullmatch(commit):
        raise SourceError("GitHub commit must be a full 40-character lowercase SHA-1")


def npm_coordinate(name: str, version: str) -> str:
    validate_npm(name, version)
    return f"npm:{name}@{version}"


def github_coordinate(owner: str, repo: str, commit: str) -> str:
    validate_github(owner, repo, commit)
    return f"github:{owner}/{repo}@{commit}"


def npm_urls(name: str, version: str) -> tuple[str, str]:
    """(metadata URL, canonical tarball URL); only the metadata URL encodes a scope's "/"."""
    validate_npm(name, version)
    basename = name.rsplit("/", 1)[-1]
    return (
        f"https://{NPM_REGISTRY}/{name.replace('/', '%2f')}/{version}",
        f"https://{NPM_REGISTRY}/{name}/-/{basename}-{version}.tgz",
    )


def check_url(url: str) -> None:
    parts = urllib.parse.urlsplit(url)
    if (
        parts.scheme != "https"
        or parts.hostname not in ALLOWED_HOSTS
        or parts.port not in (None, 443)
        or parts.username is not None
        or parts.password is not None
    ):
        raise SourceError(f"URL is not an allowlisted HTTPS source: {url}")


class RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Every URL is built here and needs no redirect, so any 3xx is an error."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: Message,
        newurl: str,
    ) -> NoReturn:
        raise SourceError(f"Refused HTTP {code} redirect from {req.full_url} to {newurl}")


_OPENER = urllib.request.build_opener(RefuseRedirects)


def fetch_allowlisted(url: str, max_bytes: int) -> bytes:
    check_url(url)
    try:
        with _OPENER.open(url, timeout=TIMEOUT_SECONDS) as response:
            data: bytes = response.read(max_bytes + 1)
    except urllib.error.HTTPError as error:
        if error.code < 500:
            raise SourceError(f"HTTP {error.code} from {url}") from error
        raise  # 5xx is the host's trouble, not the request's: let the caller retry
    if len(data) > max_bytes:
        raise SourceError(f"Response exceeds {max_bytes} bytes: {url}")
    return data


def fetch_npm(name: str, version: str, *, fetch: Fetch = fetch_allowlisted) -> FetchedArchive:
    """Download one exact npm version and verify it against the registry's integrity hash."""
    metadata_url, tarball_url = npm_urls(name, version)
    try:
        document: Any = json.loads(fetch(metadata_url, MAX_METADATA))
        dist = document["dist"]
        identity = (document["name"], document["version"])
        tarball, integrity = dist["tarball"], dist["integrity"]
    except (ValueError, KeyError, TypeError) as error:
        raise SourceError(f"Malformed registry metadata for {name}@{version}") from error
    if identity != (name, version):
        raise SourceError("Registry metadata names a different package version")
    if tarball != tarball_url:
        # The metadata's URL is data, not something to fetch: only the canonical URL is used.
        raise SourceError(f"Registry tarball URL is not canonical: {tarball}")
    if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
        raise SourceError("Registry metadata has no sha512 integrity")
    data = fetch(tarball_url, MAX_ARCHIVE)
    actual = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()
    if actual != integrity:
        raise SourceError("Tarball does not match the registry's integrity hash")
    return FetchedArchive(
        data=data,
        sha256=hashlib.sha256(data).hexdigest(),
        artifact_url=tarball_url,
        provenance_kind="publisher_verified",
        archive_root=None,
    )


def fetch_github(
    owner: str, repo: str, commit: str, *, fetch: Fetch = fetch_allowlisted
) -> FetchedArchive:
    """Download one commit from codeload directly (github.com/.../archive would redirect)."""
    validate_github(owner, repo, commit)
    url = f"https://{GITHUB_CODELOAD}/{owner}/{repo}/tar.gz/{commit}"
    data = fetch(url, MAX_ARCHIVE)
    return FetchedArchive(
        data=data,
        sha256=hashlib.sha256(data).hexdigest(),
        artifact_url=url,
        # GitHub publishes no archive hash: record the first download and keep those bytes.
        provenance_kind="tofu",
        archive_root=f"{repo}-{commit}",
    )
