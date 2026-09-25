"""Domain errors, rendered as FastAPI-style {"detail": ...} responses."""

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel


class ErrorResponse(BaseModel):
    """Body of every error response; matches FastAPI's own HTTPException shape."""

    detail: str


class AppError(Exception):
    status_code = status.HTTP_400_BAD_REQUEST
    detail = "Bad request"

    def __init__(self, detail: str | None = None) -> None:
        super().__init__(detail or self.detail)
        if detail is not None:
            self.detail = detail


class NotFoundError(AppError):
    status_code = status.HTTP_404_NOT_FOUND
    detail = "Not found"


class ConflictError(AppError):
    """The request clashes with current state, e.g. a duplicate or a finished scan."""

    status_code = status.HTTP_409_CONFLICT
    detail = "Conflict"


async def _app_error_handler(_: Request, error: Exception) -> JSONResponse:
    # Registered only for AppError; the check narrows the type without `assert`,
    # which `python -O` would strip.
    if not isinstance(error, AppError):
        raise error
    return JSONResponse(status_code=error.status_code, content={"detail": error.detail})


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, _app_error_handler)
