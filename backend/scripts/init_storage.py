"""Idempotent local bucket initialization; bounded retries while SeaweedFS starts."""

import time

from botocore.exceptions import BotoCoreError, ClientError

from app.core.config import get_settings
from app.core.storage import get_s3_client


def _error_code(error: ClientError) -> str | None:
    # Both keys are optional in botocore's error shape; never KeyError while handling one.
    return error.response.get("Error", {}).get("Code")


def initialize() -> None:
    bucket = get_settings().s3_bucket
    client = get_s3_client()
    for attempt in range(30):
        try:
            try:
                client.head_bucket(Bucket=bucket)
            except ClientError as error:
                if _error_code(error) not in {"404", "NoSuchBucket", "NotFound"}:
                    raise
                try:
                    client.create_bucket(Bucket=bucket)
                except ClientError as create_error:
                    if _error_code(create_error) != "BucketAlreadyOwnedByYou":
                        raise
            print(f"Storage ready: {bucket}")
            return
        except (BotoCoreError, ClientError):
            if attempt == 29:
                raise
            time.sleep(2)


if __name__ == "__main__":
    initialize()
