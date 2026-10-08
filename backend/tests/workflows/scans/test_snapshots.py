"""Snapshot transfers close their network streams and preserve error classification."""

import io
from typing import Any

import pytest
from botocore.exceptions import ClientError
from botocore.response import StreamingBody
from botocore.stub import Stubber

from app.core.storage import get_s3_client
from app.workflows.scans import snapshots


@pytest.mark.parametrize("outcome", ["success", "size_limit", "read_error", "write_error"])
def test_download_closes_the_response_stream(tmp_path, monkeypatch, outcome):
    data = b"archive"
    raw = io.BytesIO(data)
    body = StreamingBody(raw, len(data))
    target = tmp_path / "source.tgz"
    monkeypatch.setattr(snapshots, "MAX_ARCHIVE", len(data))
    if outcome == "size_limit":
        monkeypatch.setattr(snapshots, "MAX_ARCHIVE", len(data) - 1)
    elif outcome == "read_error":

        def fail_read(*args: Any, **kwargs: Any) -> bytes:
            raise OSError("read failed")

        monkeypatch.setattr(raw, "read", fail_read)
    elif outcome == "write_error":
        target.mkdir()

    client = get_s3_client()
    with Stubber(client) as stubber:
        stubber.add_response("get_object", {"Body": body}, {"Bucket": "sources", "Key": "s.tgz"})
        if outcome == "success":
            snapshots._download(client, "sources", "s.tgz", target)
            assert target.read_bytes() == data
        else:
            error = ValueError if outcome == "size_limit" else OSError
            with pytest.raises(error):
                snapshots._download(client, "sources", "s.tgz", target)
        stubber.assert_no_pending_responses()
    assert raw.closed


@pytest.mark.parametrize("code", ["NoSuchKey", "404", "AccessDenied"])
def test_missing_archives_are_final_but_other_storage_errors_propagate(tmp_path, code):
    client = get_s3_client()
    with Stubber(client) as stubber:
        stubber.add_client_error(
            "get_object",
            service_error_code=code,
            expected_params={"Bucket": "sources", "Key": "s.tgz"},
        )
        error = ClientError if code == "AccessDenied" else ValueError
        with pytest.raises(error):
            snapshots._download(client, "sources", "s.tgz", tmp_path / "source.tgz")
        stubber.assert_no_pending_responses()
