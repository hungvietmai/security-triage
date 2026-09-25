from typing import Literal

from pydantic import BaseModel

ServiceState = Literal["ok", "unavailable"]


class Liveness(BaseModel):
    status: Literal["ok"] = "ok"


class ReadinessChecks(BaseModel):
    postgres: ServiceState
    redis: ServiceState
    storage: ServiceState


class Readiness(BaseModel):
    status: Literal["ok", "degraded"]
    checks: ReadinessChecks
