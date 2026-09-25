"""Application-wide wiring shared by every FastAPI app built from this package."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.core.database import engine


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None]:
    yield
    # Close pooled connections so shutdown does not leave PostgreSQL sessions open.
    engine.dispose()


def setup_middleware(app: FastAPI) -> None:
    # The browser normally reaches the API through the same-origin proxy (Vite/Nginx);
    # CORS only matters when the frontend dev server calls the API directly.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=get_settings().cors_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )
