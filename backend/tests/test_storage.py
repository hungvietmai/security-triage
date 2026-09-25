from botocore.stub import Stubber

from app.config import get_settings
from app.services.storage import get_s3_client
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
