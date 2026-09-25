import time

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError
from botocore.stub import Stubber

from app.core.config import get_settings
from app.core.storage import get_s3_client
from scripts import init_storage


def test_initializer_accepts_existing_bucket_with_real_boto_client(monkeypatch):
    client = get_s3_client()
    with Stubber(client) as stubber:
        stubber.add_response("head_bucket", {}, {"Bucket": get_settings().s3_bucket})
        monkeypatch.setattr(init_storage, "get_s3_client", lambda: client)
        init_storage.initialize()
        stubber.assert_no_pending_responses()


def test_initializer_creates_missing_bucket(monkeypatch):
    client = get_s3_client()
    bucket = {"Bucket": get_settings().s3_bucket}
    with Stubber(client) as stubber:
        stubber.add_client_error(
            "head_bucket", service_error_code="404", http_status_code=404, expected_params=bucket
        )
        stubber.add_response("create_bucket", {}, bucket)
        monkeypatch.setattr(init_storage, "get_s3_client", lambda: client)
        init_storage.initialize()
        stubber.assert_no_pending_responses()


def test_s3_client_is_shared():
    assert get_s3_client() is get_s3_client()


def test_initializer_retries_while_storage_starts(monkeypatch):
    client = get_s3_client()
    bucket = {"Bucket": get_settings().s3_bucket}
    calls = {"head": 0}
    original_head = client.head_bucket

    def flaky_head_bucket(**kwargs):
        calls["head"] += 1
        if calls["head"] < 3:
            raise EndpointConnectionError(endpoint_url="http://seaweedfs:8333")
        return original_head(**kwargs)

    sleeps: list[float] = []
    monkeypatch.setattr(time, "sleep", sleeps.append)
    monkeypatch.setattr(init_storage, "get_s3_client", lambda: client)
    with Stubber(client) as stubber:
        stubber.add_response("head_bucket", {}, bucket)
        monkeypatch.setattr(client, "head_bucket", flaky_head_bucket)
        init_storage.initialize()
    assert calls["head"] == 3
    assert sleeps == [2, 2]


def test_initializer_gives_up_on_permission_errors(monkeypatch):
    client = get_s3_client()
    monkeypatch.setattr(time, "sleep", lambda _: None)
    monkeypatch.setattr(init_storage, "get_s3_client", lambda: client)
    with Stubber(client) as stubber:
        for _ in range(30):
            stubber.add_client_error("head_bucket", service_error_code="403", http_status_code=403)
        with pytest.raises(ClientError):
            init_storage.initialize()
        stubber.assert_no_pending_responses()


def test_initializer_treats_an_error_without_code_as_fatal(monkeypatch):
    client = get_s3_client()
    monkeypatch.setattr(time, "sleep", lambda _: None)
    monkeypatch.setattr(init_storage, "get_s3_client", lambda: client)

    def head_bucket(**_):
        raise ClientError({}, "HeadBucket")  # no "Error" key at all

    monkeypatch.setattr(client, "head_bucket", head_bucket)
    with pytest.raises(ClientError):
        init_storage.initialize()
