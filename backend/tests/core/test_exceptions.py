from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.exceptions import AppError, NotFoundError, register_exception_handlers


class Conflict(AppError):
    status_code = 409
    detail = "Already exists"


def make_client() -> TestClient:
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/default")
    def default() -> None:
        raise Conflict()

    @app.get("/custom")
    def custom() -> None:
        raise NotFoundError("Scan 42 not found")

    return TestClient(app)


def test_domain_errors_use_the_class_detail_and_status():
    response = make_client().get("/default")
    assert response.status_code == 409
    assert response.json() == {"detail": "Already exists"}


def test_domain_errors_accept_a_specific_detail():
    response = make_client().get("/custom")
    assert response.status_code == 404
    assert response.json() == {"detail": "Scan 42 not found"}
    assert NotFoundError.detail == "Not found"  # the override is per instance
