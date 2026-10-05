import base64
import hashlib
import io
import json
import shutil
import tarfile

import app.scanners.acquisition as acquisition

from app.scanners.acquisition import (
    AcquisitionLimits,
    acquire_source,
    unpack,
)
from app.scanners.provenance import digest


def _write_archive(path):
    package = json.dumps({"name": "curling", "version": "0.2.0"}).encode()
    source = b"module.exports = {}\n"
    with tarfile.open(path, "w:gz") as bundle:
        directory = tarfile.TarInfo("package")
        directory.type = tarfile.DIRTYPE
        bundle.addfile(directory)

        package_info = tarfile.TarInfo("package/package.json")
        package_info.size = len(package)
        bundle.addfile(package_info, io.BytesIO(package))

        source_info = tarfile.TarInfo("package/index.js")
        source_info.size = len(source)
        bundle.addfile(source_info, io.BytesIO(source))


def test_acquire_source_from_verified_local_archive(tmp_path):
    archive = tmp_path / "curling.tgz"
    _write_archive(archive)
    output = tmp_path / "output"
    output.mkdir()
    case = {
        "source_kind": "npm_tarball",
        "package_name": "curling",
        "package_version": "0.2.0",
        "artifact_url": "https://example.invalid/curling.tgz",
        "artifact_sha256": digest(archive),
        "archive_root": "package",
    }

    acquired = acquire_source(
        case,
        output,
        source_archive=archive,
        limits=AcquisitionLimits(
            max_archive_bytes=1024 * 1024,
            max_unpacked_bytes=1024 * 1024,
            max_files=10,
        ),
    )

    assert acquired.transport == "verified_local_archive"
    assert acquired.snapshot_sha256 == digest(archive)
    assert acquired.source_files == ["index.js", "package.json"]
    assert (acquired.source_path / "package.json").is_file()


def test_unpack_rejects_path_traversal(tmp_path):
    archive = tmp_path / "bad.tgz"
    with tarfile.open(archive, "w:gz") as bundle:
        data = b"x"
        info = tarfile.TarInfo("package/../escape.txt")
        info.size = len(data)
        bundle.addfile(info, io.BytesIO(data))

    try:
        unpack(
            archive,
            tmp_path / "source",
            "package",
            max_unpacked_bytes=1024,
            max_files=10,
        )
    except ValueError as exc:
        assert "Unsafe/unsupported archive entry" in str(exc)
    else:
        raise AssertionError("path traversal was accepted")


class _Response:
    def __init__(self, data, url="https://example.test/archive.tgz"):
        self.data = data
        self.url = url

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, size):
        return self.data[:size]


def test_fetch_verifies_transport_hash_and_limit(tmp_path, monkeypatch):
    target = tmp_path / "download.tgz"
    data = b"archive-bytes"
    expected = hashlib.sha256(data).hexdigest()

    monkeypatch.setattr(
        acquisition.urllib.request,
        "urlopen",
        lambda *args, **kwargs: _Response(data),
    )
    acquisition.fetch("https://example.test/archive.tgz", target, expected, len(data))
    assert target.read_bytes() == data

    monkeypatch.setattr(
        acquisition.urllib.request,
        "urlopen",
        lambda *args, **kwargs: _Response(data, "http://example.test/archive.tgz"),
    )
    try:
        acquisition.fetch("https://example.test/archive.tgz", target, expected, len(data))
    except ValueError as exc:
        assert str(exc) == "Insecure redirect"
    else:
        raise AssertionError("insecure redirect was accepted")

    monkeypatch.setattr(
        acquisition.urllib.request,
        "urlopen",
        lambda *args, **kwargs: _Response(data + b"x"),
    )
    try:
        acquisition.fetch("https://example.test/archive.tgz", target, expected, len(data))
    except ValueError as exc:
        assert "Download size limit" in str(exc)
    else:
        raise AssertionError("oversized download was accepted")


def test_verify_github_source_identity(tmp_path):
    source = tmp_path / "repo"
    source.mkdir()
    marker = source / "README.md"
    marker.write_text("pinned\n")
    commit = "a" * 40
    case = {
        "source_kind": "github_tarball",
        "source_commit": commit,
        "repository": "owner/project",
        "artifact_url": f"https://codeload.github.com/owner/project/tar.gz/{commit}",
        "archive_root": f"project-{commit}",
        "identity_files_sha256": {"README.md": digest(marker)},
    }

    acquisition.verify_source_identity(case, source)

    case["identity_files_sha256"] = {"README.md": "0" * 64}
    try:
        acquisition.verify_source_identity(case, source)
    except ValueError as exc:
        assert "Source identity mismatch" in str(exc)
    else:
        raise AssertionError("bad identity hash was accepted")


def test_acquire_source_download_and_registry_integrity(tmp_path, monkeypatch):
    archive = tmp_path / "original.tgz"
    _write_archive(archive)
    output = tmp_path / "output"
    output.mkdir()
    integrity = "sha512-" + base64.b64encode(
        hashlib.sha512(archive.read_bytes()).digest()
    ).decode()
    case = {
        "source_kind": "npm_tarball",
        "package_name": "curling",
        "package_version": "0.2.0",
        "artifact_url": "https://example.test/curling.tgz",
        "artifact_sha256": digest(archive),
        "registry_integrity": integrity,
        "archive_root": "package",
    }

    def fake_fetch(url, target, expected_hash, max_bytes):
        assert url == case["artifact_url"]
        assert expected_hash == case["artifact_sha256"]
        assert max_bytes == 1024 * 1024
        shutil.copyfile(archive, target)

    monkeypatch.setattr(acquisition, "fetch", fake_fetch)
    acquired = acquire_source(
        case,
        output,
        source_archive=None,
        limits=AcquisitionLimits(
            max_archive_bytes=1024 * 1024,
            max_unpacked_bytes=1024 * 1024,
            max_files=10,
        ),
    )

    assert acquired.transport == "https"
    assert acquired.snapshot_sha256 == digest(archive)


def test_acquire_source_rejects_bad_registry_integrity(tmp_path):
    archive = tmp_path / "curling.tgz"
    _write_archive(archive)
    output = tmp_path / "output"
    output.mkdir()
    case = {
        "source_kind": "npm_tarball",
        "package_name": "curling",
        "package_version": "0.2.0",
        "artifact_url": "https://example.invalid/curling.tgz",
        "artifact_sha256": digest(archive),
        "registry_integrity": "sha512-wrong",
        "archive_root": "package",
    }

    try:
        acquire_source(
            case,
            output,
            source_archive=archive,
            limits=AcquisitionLimits(
                max_archive_bytes=1024 * 1024,
                max_unpacked_bytes=1024 * 1024,
                max_files=10,
            ),
        )
    except ValueError as exc:
        assert str(exc) == "Registry integrity mismatch"
    else:
        raise AssertionError("bad registry integrity was accepted")
