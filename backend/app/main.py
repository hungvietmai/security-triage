from fastapi import APIRouter, FastAPI

from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging
from app.core.setup import lifespan, setup_middleware
from app.features.health.router import router as health_router
from app.features.projects.router import router as projects_router

API_PREFIX = "/api/v1"


def create_app() -> FastAPI:
    configure_logging()
    app = FastAPI(
        title="Security Triage API",
        version="0.1.0",
        description="Local development foundation. Scanner execution is not implemented yet.",
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )
    setup_middleware(app)
    register_exception_handlers(app)

    api = APIRouter(prefix=API_PREFIX)
    api.include_router(health_router)
    api.include_router(projects_router)
    app.include_router(api)
    return app


app = create_app()
