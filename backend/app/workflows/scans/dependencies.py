import uuid
from typing import Annotated

from fastapi import Depends

from app.core.database import SessionDep, get_or_raise
from app.features.scans.models import Scan
from app.workflows.scans.exceptions import ScanNotFound


def valid_scan_id(scan_id: uuid.UUID, session: SessionDep) -> Scan:
    """Resolve the `scan_id` path parameter or answer 404."""
    return get_or_raise(session, Scan, scan_id, ScanNotFound)


ScanDep = Annotated[Scan, Depends(valid_scan_id)]
