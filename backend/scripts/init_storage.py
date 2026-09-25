"""Idempotent local bucket initialization; bounded retries while SeaweedFS starts."""

import time
from contextlib import closing

from botocore.exceptions import BotoCoreError, ClientError

from app.config import get_settings
from app.services.storage import get_s3_client


def initialize() -> None:
    bucket = get_settings().s3_bucket
    with closing(get_s3_client()) as client:
        for attempt in range(30):
            try:
                try:
                    client.head_bucket(Bucket=bucket)
                except ClientError as error:
                    if error.response["Error"]["Code"] not in {"404", "NoSuchBucket", "NotFound"}:
                        raise
                    try:
                        client.create_bucket(Bucket=bucket)
                    except ClientError as create_error:
                        if create_error.response["Error"]["Code"] != "BucketAlreadyOwnedByYou":
                            raise
                print(f"Storage ready: {bucket}")
                return
            except (BotoCoreError, ClientError):
                if attempt == 29:
                    raise
                time.sleep(2)


if __name__ == "__main__":
    initialize()
