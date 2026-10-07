from app.core.exceptions import NotFoundError


class ScanNotFound(NotFoundError):
    detail = "Scan not found"


class UnitNotFound(NotFoundError):
    detail = "Location unit not found in this scan"
