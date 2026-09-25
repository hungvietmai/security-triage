from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import health, projects
from app.config import get_settings

app = FastAPI(
    title="Security Triage API",
    version="0.1.0",
    description="Local development foundation. Scanner execution is not implemented yet.",
    docs_url="/api/docs",
    redoc_url=None,
    openapi_url="/api/openapi.json",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)
app.include_router(health.router, prefix="/api/v1")
app.include_router(projects.router, prefix="/api/v1")
