import io
import json
import tarfile

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
