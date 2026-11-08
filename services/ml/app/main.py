"""PHISHGUARD ML inference API.

M0/M1 scope: bootstrap, config validation, health/version, contract-validated
request intake. The model is trained in M2; until it exists `/predict` returns
503 `upstream_unavailable` instead of a fabricated probability.
"""

from __future__ import annotations

import hmac
import logging
import uuid
from datetime import UTC, datetime

from fastapi import Depends, FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from phishguard_contracts import (
    CONTRACT_VERSION,
    FEATURE_SCHEMA_VERSION,
    SERVICE_VERSION,
    PredictRequest,
)
from pydantic import BaseModel

from .settings import ConfigError, Settings, load_settings, redacted_summary

logger = logging.getLogger("phishguard.ml")


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    contract_version: str
    env: str
    time: str
    checks: dict[str, str]


class VersionResponse(BaseModel):
    service: str
    version: str
    contract_version: str
    feature_schema_version: str


def _error(status: int, code: str, message: str, request_id: str | None = None) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={
            "error": {
                "code": code,
                "message": message,
                **({"request_id": request_id} if request_id else {}),
            }
        },
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or load_settings()

    app = FastAPI(
        title="PHISHGUARD ML API",
        version=SERVICE_VERSION,
        description="PhiUSIIL-based phishing classification with SHAP attributions.",
    )
    app.state.settings = resolved

    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):  # type: ignore[no-untyped-def]
        request_id = request.headers.get("X-Request-ID") or f"req_{uuid.uuid4().hex[:16]}"
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError):  # type: ignore[no-untyped-def]
        return _error(
            400, "invalid_url", "Request validation failed.",
            getattr(request.state, "request_id", None),
        )

    @app.exception_handler(Exception)
    async def unhandled_handler(request: Request, exc: Exception):  # type: ignore[no-untyped-def]
        request_id = getattr(request.state, "request_id", None)
        logger.exception("unhandled error request_id=%s", request_id)
        return _error(500, "internal", "Internal error.", request_id)

    def require_service_token(x_service_token: str | None = Header(default=None)) -> None:
        if not hmac.compare_digest(x_service_token or "", resolved.service_token):
            raise PermissionError("invalid service token")

    @app.exception_handler(PermissionError)
    async def auth_handler(request: Request, exc: PermissionError):  # type: ignore[no-untyped-def]
        return _error(
            401, "unauthorized", "Missing or invalid service token.",
            getattr(request.state, "request_id", None),
        )

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse(
            status="ok",
            service="ml",
            version=SERVICE_VERSION,
            contract_version=CONTRACT_VERSION,
            env=resolved.env,
            time=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            checks={
                "config": "ok",
                "model": "present" if resolved.model_path.exists() else "not_loaded",
            },
        )

    @app.get("/version", response_model=VersionResponse)
    async def version() -> VersionResponse:
        return VersionResponse(
            service="ml",
            version=SERVICE_VERSION,
            contract_version=CONTRACT_VERSION,
            feature_schema_version=FEATURE_SCHEMA_VERSION,
        )

    @app.get("/internal/config", dependencies=[Depends(require_service_token)])
    async def config_summary() -> dict[str, object]:
        return redacted_summary(resolved)

    @app.post("/predict", dependencies=[Depends(require_service_token)])
    async def predict(payload: PredictRequest, request: Request) -> JSONResponse:
        # M2 replaces this handler with real inference.
        return _error(
            503,
            "upstream_unavailable",
            "Model is not trained yet (milestone M2).",
            getattr(request.state, "request_id", None),
        )

    return app


try:
    app = create_app()
except ConfigError as exc:
    logger.error("invalid configuration: %s", exc.problems)
    raise
