"""PHISHGUARD analysis API.

M0/M1 scope: process bootstrap, configuration validation, health/version
endpoints, contract-validated request intake. M6 wires the isolated scanner's
TLS and HTTP evidence plus the threat-intelligence engine into
`/internal/analyze`; engines that do not exist yet and M7 risk aggregation are
reported explicitly as unavailable, never as safe.
"""

from __future__ import annotations

import hmac
import logging
import uuid
from datetime import UTC, datetime

from fastapi import Depends, FastAPI, Header, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from phishguard_contracts import (
    CONTRACT_VERSION,
    FEATURE_SCHEMA_VERSION,
    SERVICE_VERSION,
    ScanRequest,
)
from pydantic import BaseModel, Field

from persistence import PersistenceError, build_scan_store, persist_scan

from .orchestration import build_scan_result
from .settings import ConfigError, Settings, load_settings, redacted_summary

logger = logging.getLogger("phishguard.analysis")


class HealthResponse(BaseModel):
    status: str = Field(description="ok | degraded")
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
    """Application factory. Raises ConfigError if the environment is invalid."""
    resolved = settings or load_settings()

    app = FastAPI(
        title="PHISHGUARD Analysis API",
        version=SERVICE_VERSION,
        description="Orchestrates deterministic engines and risk aggregation.",
    )
    app.state.settings = resolved

    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(resolved.allowed_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "Authorization", "X-Request-ID"],
    )

    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):  # type: ignore[no-untyped-def]
        request_id = request.headers.get("X-Request-ID") or f"req_{uuid.uuid4().hex[:16]}"
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError):  # type: ignore[no-untyped-def]
        request_id = getattr(request.state, "request_id", None)
        return _error(400, "invalid_url", "Request validation failed.", request_id)

    @app.exception_handler(Exception)
    async def unhandled_handler(request: Request, exc: Exception):  # type: ignore[no-untyped-def]
        request_id = getattr(request.state, "request_id", None)
        logger.exception("unhandled error request_id=%s", request_id)
        return _error(500, "internal", "Internal error.", request_id)

    def require_service_token(x_service_token: str | None = Header(default=None)) -> None:
        expected = resolved.service_token
        presented = x_service_token or ""
        if not hmac.compare_digest(presented, expected):
            raise PermissionError("invalid service token")

    @app.exception_handler(PermissionError)
    async def auth_handler(request: Request, exc: PermissionError):  # type: ignore[no-untyped-def]
        request_id = getattr(request.state, "request_id", None)
        return _error(401, "unauthorized", "Missing or invalid service token.", request_id)

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse(
            status="ok",
            service="analysis",
            version=SERVICE_VERSION,
            contract_version=CONTRACT_VERSION,
            env=resolved.env,
            time=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            checks={"config": "ok", "persistence": resolved.persistence},
        )

    @app.get("/version", response_model=VersionResponse)
    async def version() -> VersionResponse:
        return VersionResponse(
            service="analysis",
            version=SERVICE_VERSION,
            contract_version=CONTRACT_VERSION,
            feature_schema_version=FEATURE_SCHEMA_VERSION,
        )

    @app.get("/internal/config", dependencies=[Depends(require_service_token)])
    async def config_summary() -> dict[str, object]:
        """Redacted configuration, for operator debugging. Never returns secrets."""
        return redacted_summary(resolved)

    @app.post("/internal/analyze", dependencies=[Depends(require_service_token)])
    async def analyze(
        payload: ScanRequest,
        x_authenticated_user_id: str | None = Header(default=None),
    ) -> JSONResponse:
        # The request is contract-validated before any engine runs. M6 executes
        # the URL, transport (TLS/HTTP) and threat-intelligence engines; the
        # result is explicitly `failed` because M7 risk aggregation is absent.
        result = await run_in_threadpool(build_scan_result, payload, resolved)

        # Persist the assessment server-side using the service role. A
        # persistence failure degrades gracefully: the scan result is still
        # returned to the client and never treated as benign.
        try:
            store = build_scan_store(resolved)
            if store is not None:
                persist_scan(
                    store,
                    result,
                    user_id=x_authenticated_user_id,
                    retention_days=resolved.scan_retention_days,
                )
        except PersistenceError as exc:
            logger.warning("scan persistence failed: %s", exc)

        return JSONResponse(status_code=200, content=result.model_dump(mode="json"))

    return app


try:
    app = create_app()
except ConfigError as exc:  # fail fast: uvicorn exits with a clear reason
    logger.error("invalid configuration: %s", exc.problems)
    raise
