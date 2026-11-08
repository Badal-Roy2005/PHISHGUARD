"""Analysis orchestration for PHISHGUARD.

M7 combines the M3 URL engine, M6 transport engines and M5B threat-intelligence
evidence into one deterministic, policy-versioned risk assessment. Engines that
do not exist yet remain explicit ``unknown``/``skipped`` and reduce coverage;
they are never treated as safe. ML probability is exposed separately and is not
part of the heuristic risk score.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import asdict

from phishguard_contracts import (
    EngineReport,
    Engines,
    Finding,
    ScanRequest,
    ScanResult,
)

from certificate_transparency import CertificateTransparencyClient
from risk_assessment import (
    AssessmentInput,
    assess_risk,
    build_explanation,
)
from threat_intel import (
    DEFAULT_CACHE,
    IntelEngineResult,
    ProviderConfig,
    SafeBrowsingProvider,
    TTLCache,
    URLhausProvider,
    run_intel_engine,
    utc_now_iso,
)
from url_analysis import analyze_url

from .settings import Settings
from .transport import ScannerCallable, run_transport_assessment

URL_ENGINE_SOURCE = "phishguard-url@0.1.0"


def build_intel_providers(
    settings: Settings,
    *,
    cache: TTLCache | None = None,
) -> list[SafeBrowsingProvider | URLhausProvider]:
    """Build provider adapters from validated server-side settings."""
    config = ProviderConfig(
        timeout_seconds=settings.intel_timeout_seconds,
        max_response_bytes=settings.intel_max_response_bytes,
        max_retries=settings.intel_max_retries,
    )
    shared_cache = cache
    if shared_cache is None and settings.intel_cache_enabled:
        shared_cache = DEFAULT_CACHE
    return [
        SafeBrowsingProvider(
            settings.safe_browsing_key,
            config=config,
            cache=shared_cache,
            ttl_seconds=settings.intel_safe_browsing_cache_ttl_seconds,
        ),
        URLhausProvider(
            settings.urlhaus_key,
            config=config,
            cache=shared_cache,
            ttl_seconds=settings.intel_urlhaus_cache_ttl_seconds,
        ),
    ]


def _elapsed_ms(start: float) -> float:
    return round((time.monotonic() - start) * 1000, 3)


def _not_implemented(engine: str, message: str, *, status: str = "unknown") -> EngineReport:
    return EngineReport(
        engine=engine,  # type: ignore[arg-type]
        status=status,  # type: ignore[arg-type]
        findings=[],
        evidence={},
        source="not-implemented",
        duration_ms=0.0,
        error=message,
    )


def _run_url_engine(url: str) -> tuple[EngineReport, str]:
    start = time.monotonic()
    try:
        result = analyze_url(url)
    except ValueError as exc:
        message = str(exc)[:1024]
        return (
            EngineReport(
                engine="url",
                status="error",
                findings=[],
                evidence={},
                source=URL_ENGINE_SOURCE,
                duration_ms=_elapsed_ms(start),
                error=message,
            ),
            url,
        )

    findings: list[Finding] = []
    for index, finding in enumerate(result.findings):
        findings.append(
            Finding(
                id=finding.rule_id[:128],
                title=finding.rule_id.replace("_", " ").title()[:256],
                severity=finding.severity,
                detail=finding.explanation[:4096],
                evidence_ref=f"url.findings.{index}",
            )
        )

    evidence = {
        "finding_count": len(findings),
        "findings": [
            {
                "id": finding.rule_id,
                "severity": finding.severity,
                "evidence": finding.evidence,
                "url_component": finding.url_component,
            }
            for finding in result.findings
        ],
        "ml_features": result.extracted_features_for_ml,
        "features": {
            key: value
            for key, value in asdict(result.url_features).items()
            if key not in {"path", "query", "fragment"}
        },
    }
    return (
        EngineReport(
            engine="url",
            status="ok",
            findings=findings,
            evidence=evidence,
            source=URL_ENGINE_SOURCE,
            duration_ms=_elapsed_ms(start),
        ),
        result.normalized_url,
    )


def _disabled_intel() -> IntelEngineResult:
    return IntelEngineResult(
        status="skipped",
        evidence={
            "providers": {},
            "provider_statuses": {},
            "match_providers": [],
            "no_match_providers": [],
            "unavailable_providers": [],
            "error_providers": [],
            "cache_hits": [],
            "policy": {
                "no_match_is_not_safe": True,
                "provider_failure_is_not_safe": True,
                "missing_credentials_is_not_safe": True,
            },
            "disabled_by_request": True,
        },
        source="threat-intel",
        error="Threat intelligence was disabled by the request options.",
    )


def build_scan_result(
    payload: ScanRequest,
    settings: Settings,
    *,
    providers: list[SafeBrowsingProvider | URLhausProvider] | None = None,
    scanner: ScannerCallable | None = None,
    ct_client: CertificateTransparencyClient | None = None,
) -> ScanResult:
    """Run available engines and return a contract-valid M7 assessment.

    The top-level status is ``partial`` while any engine is not ``ok``. This is
    deliberate: missing evidence must not be promoted to an overall safe
    verdict, and the risk assessment reports coverage explicitly.
    """
    start = time.monotonic()
    created_at = utc_now_iso()

    url_report, normalized_url = _run_url_engine(payload.url)

    tls_report, http_report, transport_evidence = run_transport_assessment(
        payload.url,
        settings,
        include_ct=payload.options.include_ct,
        timeout_ms=payload.options.timeout_ms,
        scanner=scanner,
        ct_client=ct_client,
    )

    if payload.options.include_intel:
        owns_providers = providers is None
        if providers is None:
            providers = build_intel_providers(settings)
        try:
            intel_result = run_intel_engine(
                payload.url,
                providers,
                deadline_seconds=payload.options.timeout_ms / 1000,
            )
        finally:
            if owns_providers:
                for provider in providers:
                    provider.close()
    else:
        intel_result = _disabled_intel()

    intel_report = intel_result.to_engine_report()
    ml_report = _not_implemented(
        "ml",
        "ML inference is not wired into scan orchestration yet; probability is separate.",
    )
    community_report = _not_implemented(
        "community",
        "Community reports are not implemented yet (M8).",
        status="skipped",
    )
    engines = Engines(
        ml=ml_report,
        url=url_report,
        tls=tls_report,
        http=http_report,
        intel=intel_report,
        community=community_report,
    )

    assessment = assess_risk(
        AssessmentInput(
            url=url_report,
            tls=tls_report,
            http=http_report,
            intel=intel_report,
            ml=ml_report,
            redirect_chain=tuple(transport_evidence.get("redirect_chain") or []),
            scanner_status=transport_evidence.get("scanner_status"),
            scanner_error=transport_evidence.get("scanner_error"),
        )
    )
    explanation = build_explanation(assessment)
    engine_reports = (
        engines.ml,
        engines.url,
        engines.tls,
        engines.http,
        engines.intel,
        engines.community,
    )
    status = "complete" if all(report.status == "ok" for report in engine_reports) else "partial"

    return ScanResult(
        scan_id=str(uuid.uuid4()),
        url=payload.url,
        normalized_url=normalized_url,
        status=status,
        created_at=created_at,
        completed_at=utc_now_iso(),
        duration_ms=_elapsed_ms(start),
        risk=assessment,
        engines=engines,
        explanation=explanation,
        evidence={
            "orchestration": {
                "risk_assessment": "implemented",
                "milestone": "M7",
                "policy_version": assessment.policy.version,
                "covered_weight": assessment.confidence.covered_weight,
                "incomplete": assessment.incomplete,
                "note": (
                    "Risk is a provisional heuristic score. Missing evidence is "
                    "reported as incomplete, never as safe."
                ),
            },
            "transport": transport_evidence,
            "intel_provider_statuses": intel_result.evidence.get(
                "provider_statuses", {}
            ),
        },
    )
