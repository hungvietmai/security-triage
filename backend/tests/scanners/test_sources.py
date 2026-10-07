import base64
import hashlib
import io
import json
import urllib.error
import urllib.request
from email.message import Message
from typing import Any

import pytest

from app.scanners import sources
from app.scanners.sources import (
    RefuseRedirects,
    SourceError,
    check_url,
    fetch_allowlisted,
    fetch_github,
    fetch_npm,
    github_coordinate,
    npm_coordinate,
    npm_urls,
)

COMMIT = "5d362353550a8baa42bba34edd26e5fb86d41b60"


@pytest.mark.parametrize(
    ("name", "version"),
    [("curling", "0.2.0"), ("@babel/core", "7.0.0"), ("a-b.c_d~e", "1.0.0-rc.1+build.5")],
)
def test_valid_npm_coordinates(name, version):
    assert npm_coordinate(name, version) == f"npm:{name}@{version}"


@pytest.mark.parametrize(
    ("name", "version"),
    [
        ("Curling", "0.2.0"),  # uppercase
        (".hidden", "1.0.0"),
        ("_private", "1.0.0"),
        ("../etc", "1.0.0"),
        ("curling/../x", "1.0.0"),
        ("%2e%2e", "1.0.0"),
        ("@scope/", "1.0.0"),
        ("a" * 215, "1.0.0"),
        ("curling\n", "0.2.0"),
        ("curling", "latest"),
        ("curling", "^0.2.0"),
        ("curling", "0.2"),
        ("curling", "01.2.3"),
        ("curling", "0.2.0\n"),
    ],
)
def test_invalid_npm_coordinates_are_rejected(name, version):
    with pytest.raises(SourceError):
        npm_coordinate(name, version)


@pytest.mark.parametrize(
    ("owner", "repo", "commit"),
    [
        ("-owner", "repo", COMMIT),
        ("o" * 40, "repo", COMMIT),
        ("owner/x", "repo", COMMIT),
        ("owner", "..", COMMIT),
        ("owner", ".", COMMIT),
        ("owner", "re/po", COMMIT),
        ("owner", "%2e%2e", COMMIT),
        ("owner", "repo", COMMIT.upper()),
        ("owner", "repo", COMMIT[:7]),
        ("owner", "repo", "main"),
    ],
)
def test_invalid_github_coordinates_are_rejected(owner, repo, commit):
    with pytest.raises(SourceError):
        github_coordinate(owner, repo, commit)


def test_github_coordinate_and_npm_urls_are_canonical():
    assert github_coordinate("cristianstaicu", "SecBench.js", COMMIT) == (
        f"github:cristianstaicu/SecBench.js@{COMMIT}"
    )
    assert npm_urls("@babel/core", "7.0.0") == (
        "https://registry.npmjs.org/@babel%2fcore/7.0.0",
        "https://registry.npmjs.org/@babel/core/-/core-7.0.0.tgz",
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://registry.npmjs.org/curling/0.2.0",
        "https://evil.example/curling",
        "https://registry.npmjs.org.evil.example/x",
        "https://registry.npmjs.org:8443/curling",
        "https://user:pw@registry.npmjs.org/curling",
        "https://github.com/owner/repo/archive/x.tar.gz",
        "file:///etc/passwd",
    ],
)
def test_only_allowlisted_https_urls_are_fetched(url):
    with pytest.raises(SourceError):
        check_url(url)


def test_redirects_are_refused_even_to_an_allowlisted_host():
    request = urllib.request.Request("https://registry.npmjs.org/curling/0.2.0")
    with pytest.raises(SourceError, match="Refused HTTP 302 redirect"):
        RefuseRedirects().redirect_request(
            request, io.BytesIO(), 302, "Found", Message(), "https://evil.example/"
        )


class _Response(io.BytesIO):
    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def _opener(outcome: Any) -> Any:
    class Opener:
        def open(self, url: str, timeout: float) -> _Response:
            assert timeout == sources.TIMEOUT_SECONDS
            if isinstance(outcome, Exception):
                raise outcome
            return _Response(outcome)

    return Opener()


def test_fetch_allowlisted_reads_limits_and_classifies_http_errors(monkeypatch):
    url = "https://registry.npmjs.org/curling/0.2.0"
    monkeypatch.setattr(sources, "_OPENER", _opener(b"12345"))
    assert fetch_allowlisted(url, 5) == b"12345"
    with pytest.raises(SourceError, match="exceeds 4 bytes"):
        fetch_allowlisted(url, 4)

    not_found = urllib.error.HTTPError(url, 404, "Not Found", Message(), None)
    monkeypatch.setattr(sources, "_OPENER", _opener(not_found))
    with pytest.raises(SourceError, match="HTTP 404"):
        fetch_allowlisted(url, 5)

    unavailable = urllib.error.HTTPError(url, 503, "Unavailable", Message(), None)
    monkeypatch.setattr(sources, "_OPENER", _opener(unavailable))
    with pytest.raises(urllib.error.HTTPError):
        fetch_allowlisted(url, 5)


def _registry(tarball: bytes, fetched: list[str] | None = None, **overrides: Any) -> Any:
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(tarball).digest()).decode()
    document: dict[str, Any] = {
        "name": "curling",
        "version": "0.2.0",
        "dist": {
            "tarball": "https://registry.npmjs.org/curling/-/curling-0.2.0.tgz",
            "integrity": integrity,
        },
    }
    document.update(overrides)

    def fetch(url: str, max_bytes: int) -> bytes:
        if fetched is not None:
            fetched.append(url)
        return json.dumps(document).encode() if url.endswith("/0.2.0") else tarball

    return fetch


def test_fetch_npm_verifies_the_registry_integrity():
    fetched: list[str] = []
    archive = fetch_npm("curling", "0.2.0", fetch=_registry(b"tarball bytes", fetched))
    assert archive.sha256 == hashlib.sha256(b"tarball bytes").hexdigest()
    assert archive.provenance_kind == "publisher_verified"
    assert fetched == [
        "https://registry.npmjs.org/curling/0.2.0",
        "https://registry.npmjs.org/curling/-/curling-0.2.0.tgz",
    ]


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"version": "0.2.1"}, "different package version"),
        (
            {"dist": {"tarball": "https://evil.example/x.tgz", "integrity": "sha512-x"}},
            "not canonical",
        ),
        (
            {
                "dist": {
                    "tarball": "https://registry.npmjs.org/curling/-/curling-0.2.0.tgz",
                    "integrity": "sha1-abc",
                }
            },
            "no sha512 integrity",
        ),
        ({"dist": None}, "Malformed registry metadata"),
    ],
)
def test_fetch_npm_rejects_untrustworthy_metadata(overrides, message):
    with pytest.raises(SourceError, match=message):
        fetch_npm("curling", "0.2.0", fetch=_registry(b"x", **overrides))


def test_fetch_npm_rejects_a_tampered_tarball():
    honest = _registry(b"original")

    def tampered(url: str, max_bytes: int) -> bytes:
        return honest(url, max_bytes) if url.endswith("/0.2.0") else b"tampered"

    with pytest.raises(SourceError, match="integrity hash"):
        fetch_npm("curling", "0.2.0", fetch=tampered)


def test_fetch_github_builds_the_codeload_url_and_records_tofu():
    fetched: list[str] = []

    def fetch(url: str, max_bytes: int) -> bytes:
        fetched.append(url)
        return b"tar"

    archive = fetch_github("cristianstaicu", "SecBench.js", COMMIT, fetch=fetch)
    assert fetched == [f"https://codeload.github.com/cristianstaicu/SecBench.js/tar.gz/{COMMIT}"]
    assert (archive.provenance_kind, archive.archive_root) == ("tofu", f"SecBench.js-{COMMIT}")
