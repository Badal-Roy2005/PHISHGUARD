"""M6 transport engines: TLS and HTTP security assessment.

The scanner is the only component that fetches the target URL. This module
consumes its evidence once, optionally adds a bounded Certificate Transparency
lookup, and returns two contract engine reports. Missing or failed evidence is
never converted into a safe verdict.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from phishguard_contracts import EngineReport, Finding

from certificate_transparency import (
    CertificateTransparencyClient,
    CTConfig,
    CTReason,
    CTResult,
    CTStatus,
    skipped_result,
)
from http_security import assess_http_security, sanitize_url_for_evidence
from scanner import ScannerConfig, scan_url
from scanner import ScanResult as ScannerResult
from tls_assessment import assess_tls

from .settings import Settings

SCANNER_SOURCE = "phishguard-scanner@0.1.0"
TLS_SOURCE = "phishguard-tls@0.1.0"
HTTP_SOURCE = "phishguard-http@0.1.0"

ScannerCallable = Callable[[str, ScannerConfig], ScannerResult]


def _elapsed_ms(start: float) -> float:
    return round((time.monotonic() - start) * 1000, 3)


def _to_findings(items: tuple[dict[str, Any], ...], prefix: str) -> list[Finding]:
    findings: list[Finding] = []
    for index, item in enumerate(items):
        findings.append(
            Finding(
                id=str(item.get("id") or f"{prefix}-finding-{index}")[:128],
                title=str(item.get("title") or "Security finding")[:256],
                severity=item.get("severity", "info"),
                detail=(str(item["detail"])[:4096] if item.get("detail") else None),
                evidence_ref=item.get("evidence_ref") or f"{prefix}.findings.{index}",
            )
        )
    return findings


def _combine_error(primary: str | None, secondary: str | None) -> str | None:
    parts = [part for part in (primary, secondary) if part]
    if not parts:
        return None
    return "; ".join(parts)[:1024]


def _run_ct_lookup(
    final_url: str,
    settings: Settings,
    *,
    include_ct: bool,
    deadline: float,
    client: CertificateTransparencyClient | None,
) -> CTResult:
    domain = urlparse(final_url).hostname or ""
    if not include_ct:
        return skipped_result(
            domain,
            reason=CTReason.NOT_REQUESTED,
            error="Certificate Transparency was not requested.",
        )
    if not settings.ct_enabled:
        return skipped_result(
            domain,
            reason=CTReason.DISABLED_BY_CONFIG,
            error="Certificate Transparency is disabled by server configuration.",
        )
    if urlparse(final_url).scheme.lower() != "https":
        return skipped_result(
            domain,
            reason=CTReason.NOT_HTTPS,
            error="Certificate Transparency is not applicable to an HTTP URL.",
        )

    owns_client = client is None
    ct_client = client or CertificateTransparencyClient(
        CTConfig(
            timeout_seconds=settings.ct_timeout_seconds,
            max_response_bytes=settings.ct_max_response_bytes,
            max_records=settings.ct_max_records,
        )
    )
    try:
        return ct_client.lookup(final_url, deadline=deadline)
    finally:
        if owns_client:
            ct_client.close()


def run_transport_assessment(
    url: str,
    settings: Settings,
    *,
    include_ct: bool = False,
    timeout_ms: int = 8000,
    scanner: ScannerCallable | None = None,
    ct_client: CertificateTransparencyClient | None = None,
) -> tuple[EngineReport, EngineReport, dict[str, Any]]:
    """Run the scanner once, then produce the TLS and HTTP engine reports."""
    start = time.monotonic()
    scanner = scanner or scan_url
    budget_seconds = max(1.0, min(30.0, timeout_ms / 1000))
    config = ScannerConfig(
        allow_loopback=settings.scanner_allow_loopback_for_tests,
        connection_timeout=min(10.0, budget_seconds),
        total_deadline=budget_seconds,
    )

    try:
        scan = scanner(url, config)
    except Exception as exc:  # noqa: BLE001 - a scanner crash must be explicit
        scan = ScannerResult(
            scan_id="scanner-error",
            url=url,
            status="failed",
            risk_band=None,
            findings=[],
            evidence={"error": f"Scanner failed: {type(exc).__name__}", "final_url": url},
            duration_ms=0.0,
        )

    scan_evidence = scan.evidence or {}
    final_url = str(scan_evidence.get("final_url") or url)
    redirect_chain = list(scan_evidence.get("redirect_chain") or [url])
    scan_error = scan_evidence.get("error")
    if scan.status == "failed" and not scan_error:
        scan_error = "The scanner did not produce a usable response."

    tls_assessment = assess_tls(
        final_url,
        scan_evidence.get("tls_information"),
        scan_error=scan_error,
        redirect_chain=redirect_chain,
    )

    ct_result = _run_ct_lookup(
        final_url,
        settings,
        include_ct=include_ct,
        deadline=start + budget_seconds,
        client=ct_client,
    )

    tls_status = tls_assessment.status
    tls_error = tls_assessment.error
    tls_evidence = dict(tls_assessment.evidence)
    tls_evidence["ct"] = ct_result.to_evidence()
    tls_evidence["scanner_status"] = scan.status
    tls_evidence["scanner_source"] = SCANNER_SOURCE

    if include_ct and ct_result.status != CTStatus.OK:
        if tls_status in {"ok", "partial"}:
            tls_status = "partial"
        tls_error = _combine_error(tls_error, ct_result.error)

    tls_findings = _to_findings(tls_assessment.findings, "tls")
    if (
        include_ct
        and ct_result.status == CTStatus.OK
        and ct_result.certificate_count == 0
    ):
        tls_findings.append(
            Finding(
                id="ct_no_certificates",
                title="No Certificate Transparency records found",
                severity="low",
                detail=(
                    "crt.sh returned no public certificates for the target domain. "
                    "This may indicate incomplete CT coverage and is not a safe verdict."
                ),
                evidence_ref="tls.ct.certificate_count",
            )
        )

    tls_report = EngineReport(
        engine="tls",
        status=tls_status,  # type: ignore[arg-type]
        findings=tls_findings,
        evidence=tls_evidence,
        source=TLS_SOURCE,
        duration_ms=_elapsed_ms(start),
        error=tls_error[:1024] if tls_error else None,
    )

    http_assessment = assess_http_security(
        final_url,
        scan_evidence.get("response_headers"),
        http_status=scan_evidence.get("http_status"),
        set_cookie_headers=scan_evidence.get("set_cookie_headers"),
        redirect_chain=redirect_chain,
        scan_error=scan_error,
    )
    http_evidence = dict(http_assessment.evidence)
    http_evidence["scanner_status"] = scan.status
    http_evidence["scanner_source"] = SCANNER_SOURCE
    http_evidence["content_type"] = scan_evidence.get("content_type")

    http_report = EngineReport(
        engine="http",
        status=http_assessment.status,  # type: ignore[arg-type]
        findings=_to_findings(http_assessment.findings, "http"),
        evidence=http_evidence,
        source=HTTP_SOURCE,
        duration_ms=_elapsed_ms(start),
        error=http_assessment.error[:1024] if http_assessment.error else None,
    )

    extra = {
        "scanner_status": scan.status,
        "scanner_duration_ms": scan.duration_ms,
        "scanner_error": scan_error,
        "final_url": sanitize_url_for_evidence(final_url),
        "redirect_chain": [
            sanitize_url_for_evidence(hop) for hop in redirect_chain
        ],
        "ct_status": ct_result.status,
        "ct_reason": ct_result.reason,
    }
    return tls_report, http_report, extra
