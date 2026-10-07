import uuid
from typing import Any

from fastapi import APIRouter, status

from app.core.config import get_settings
from app.core.database import SessionDep
from app.core.exceptions import ErrorResponse
from app.core.pagination import PageParamsDep
from app.features.projects.dependencies import ProjectDep
from app.workflows.scans import service
from app.workflows.scans.dependencies import ScanDep
from app.workflows.scans.schemas import (
    ScanAccepted,
    ScanCreate,
    ScanRead,
    Tier,
    Tool,
    UnitDetail,
    UnitPage,
)
from app.workflows.scans.task import run_scan

router = APIRouter(tags=["scans"])
NOT_FOUND: dict[int | str, dict[str, Any]] = {
    404: {"model": ErrorResponse, "description": "Not found"}
}


@router.post(
    "/projects/{project_id}/scans",
    response_model=ScanAccepted,
    status_code=status.HTTP_202_ACCEPTED,
    responses=NOT_FOUND,
)
def create_scan(project: ProjectDep, payload: ScanCreate, session: SessionDep) -> ScanAccepted:
    """Queue a scan of a named npm package version or GitHub commit; the server builds the URL."""
    scan = service.create_scan(session, project, payload, bucket=get_settings().s3_bucket)
    run_scan.delay(str(scan.id))
    return ScanAccepted(scan_id=scan.id, snapshot_id=scan.snapshot_id, status=scan.status)


@router.get("/scans/{scan_id}", response_model=ScanRead, responses=NOT_FOUND)
def get_scan(scan: ScanDep, session: SessionDep) -> ScanRead:
    """Status with timestamps, tool runs and the number of units per priority."""
    return ScanRead.model_validate(service.describe_scan(session, scan), from_attributes=True)


@router.get("/scans/{scan_id}/units", response_model=UnitPage, responses=NOT_FOUND)
def list_units(
    scan: ScanDep,
    session: SessionDep,
    page: PageParamsDep,
    tier: Tier | None = None,
    tool: Tool | None = None,
) -> UnitPage:
    """Location units in queue order (P1, P2, U, P3, P4, then unit_key)."""
    return UnitPage.from_result(service.list_units(session, scan, page=page, tier=tier, tool=tool))


@router.get("/scans/{scan_id}/units/{unit_id}", response_model=UnitDetail, responses=NOT_FOUND)
def get_unit(scan: ScanDep, unit_id: uuid.UUID, session: SessionDep) -> UnitDetail:
    """Evidence record, reason, policy provenance and the raw findings of one unit."""
    return UnitDetail.model_validate(service.get_unit(session, scan, unit_id))
