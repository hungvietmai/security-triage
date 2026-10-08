import urllib.error

from botocore.exceptions import BotoCoreError, ClientError
from sqlalchemy import exc as sa_exc

from app.core.exceptions import NotFoundError


class ScanNotFound(NotFoundError):
    detail = "Scan not found"


class UnitNotFound(NotFoundError):
    detail = "Location unit not found in this scan"


INFRA_ERRORS: tuple[type[Exception], ...] = (
    sa_exc.OperationalError,
    sa_exc.InterfaceError,
    sa_exc.TimeoutError,
    BotoCoreError,
    ClientError,
    # Network trouble reaching the registry or codeload; HTTP 4xx is a SourceError instead.
    urllib.error.URLError,
    TimeoutError,
    ConnectionError,
)
