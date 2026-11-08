"""M7 deterministic risk assessment tests. No network or ML calls."""

from __future__ import annotations

import pytest
from phishguard_contracts import EngineReport, Finding

from risk_assessment import (
    DEFAULT_POLICY,
    AssessmentInput,
    AssessmentInputError,
    BrandAssessment,
    RiskPolicy,
    assess_risk,
    band_for_score,
    build_explanation,
)


def _finding(
    finding_id: str,
    severity: str = "medium",
    *,
    detail: str = "observed detail",
    title: str = "Observed finding",
) -> Finding:
    return Finding(
        id=finding_id,
        title=title,
        severity=severity,  # type: ignore[arg-type]
        detail=detail,
    )


def _report(
    engine: str,
    *,
    status: str = "ok",
    findings: list[Finding] | None = None,
    evidence: dict | None = None,
    error: str | None = None,
) -> EngineReport:
    return EngineReport(
        engine=engine,  # type: ignore[arg-type]
        status=status,  # type: ignore[arg-type]
        findings=findings or [],
        evidence=evidence or {},
        source=f"test-{engine}",
        duration_ms=1.0,
        error=error,
    )


def _base_input(**overrides) -> AssessmentInput:
    values = {
        "url": _report("url"),
        "tls": _report("tls"),
        "http": _report("http"),
        "intel": _report(
            "intel",
            evidence={
                "provider_statuses": {
                    "google_safe_browsing": "no_match",
                    "urlhaus": "no_match",
                }
            },
        ),
        "brand": BrandAssessment(status="no_match"),
        "redirect_chain": ("https://example.com/",),
        "scanner_status": "complete",
    }
    values.update(overrides)
    return AssessmentInput(**values)


def _intel_match() -> EngineReport:
    return _report(
        "intel",
        findings=[_finding("intel-sb-0", "high")],
        evidence={
            "provider_statuses": {
                "google_safe_browsing": "match",
                "urlhaus": "no_match",
            }
        },
    )


def test_clean_evidence_is_low_but_not_safe() -> None:
    risk = assess_risk(_base_input())

    assert risk.score == 0
    assert risk.band == "low"
    assert risk.incomplete is False
    assert "not a safety guarantee" in risk.verdict
    assert risk.confidence.covered_weight == 100


def test_all_unavailable_is_insufficient() -> None:
    risk = assess_risk(
        AssessmentInput(
            url=_report("url", status="error", error="url engine failed"),
            tls=_report("tls", status="unknown", error="tls unavailable"),
            http=_report("http", status="error", error="http failed"),
            intel=_report("intel", status="skipped", error="disabled"),
            brand=None,
            redirect_chain=(),
            scanner_status="failed",
            scanner_error="scanner failed",
        )
    )

    assert risk.score is None
    assert risk.band == "insufficient_evidence"
    assert risk.incomplete is True
    assert risk.confidence.covered_weight == 0
    assert "url_unavailable" in risk.reason_codes
    assert "tls_unavailable" in risk.reason_codes
    assert "http_unavailable" in risk.reason_codes
    assert "intel_unavailable" in risk.reason_codes
    assert "brand_evidence_unavailable" in risk.reason_codes


def test_no_match_is_not_proof_of_safety() -> None:
    risk = assess_risk(
        AssessmentInput(
            url=_report("url", status="unknown"),
            tls=_report("tls", status="unknown"),
            http=_report("http", status="unknown"),
            intel=_report(
                "intel",
                evidence={"provider_statuses": {"google_safe_browsing": "no_match"}},
            ),
            brand=None,
            redirect_chain=(),
            scanner_status="failed",
        )
    )

    assert risk.score is None
    assert risk.band == "insufficient_evidence"
    assert "intel_no_match" in risk.reason_codes
    assert risk.band != "low"


def test_intel_match_adds_its_weight_once() -> None:
    intel = _report(
        "intel",
        findings=[
            _finding("intel-sb-0", "high"),
            _finding("intel-urlhaus-1", "high"),
        ],
        evidence={
            "provider_statuses": {
                "google_safe_browsing": "match",
                "urlhaus": "match",
            }
        },
    )
    risk = assess_risk(_base_input(intel=intel))

    assert risk.score == 35
    assert risk.band == "guarded"
    intel_factors = [f for f in risk.factors if f.category == "intel"]
    assert sum(f.contribution for f in intel_factors) == 35
    assert [f.reason_code for f in intel_factors].count("intel_confirmed_match") == 1


def test_ml_probability_is_not_substituted_for_aggregate_score() -> None:
    high_ml = _report(
        "ml",
        evidence={"probability_phishing": 0.99, "label": "phishing", "status": "ok"},
    )
    low_ml = _report(
        "ml",
        evidence={"probability_phishing": 0.01, "label": "legitimate", "status": "ok"},
    )
    high = assess_risk(_base_input(ml=high_ml))
    low = assess_risk(_base_input(ml=low_ml))

    assert high.score == low.score == 0
    assert high.band == low.band == "low"
    assert high.model_probability is not None
    assert low.model_probability is not None
    assert high.model_probability.probability_phishing == 0.99
    assert low.model_probability.probability_phishing == 0.01
    assert high.model_probability.used_in_risk_score is False
    ml_factor = next(f for f in high.factors if f.category == "ml")
    assert ml_factor.contribution == 0


def test_malformed_ml_probability_is_not_used() -> None:
    ml = _report("ml", evidence={"probability_phishing": "not-a-number"})
    risk = assess_risk(_base_input(ml=ml))

    assert risk.score == 0
    assert risk.model_probability is None
    assert "ml_probability_malformed" in risk.reason_codes


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, "low"),
        (19, "low"),
        (20, "guarded"),
        (39, "guarded"),
        (40, "suspicious"),
        (69, "suspicious"),
        (70, "high"),
        (100, "high"),
    ],
)
def test_score_boundaries(score: int, expected: str) -> None:
    assert band_for_score(score) == expected


def test_duplicate_tls_findings_are_capped() -> None:
    tls = _report(
        "tls",
        findings=[
            _finding("tls_certificate_expired", "critical"),
            _finding("tls_certificate_untrusted", "critical"),
            _finding("tls_weak_protocol", "high"),
        ],
    )
    risk = assess_risk(_base_input(tls=tls))

    tls_contributions = [
        f.contribution for f in risk.factors if f.category == "tls"
    ]
    assert sum(tls_contributions) == 15
    assert max(tls_contributions) == 15


def test_transport_signals_are_not_double_counted() -> None:
    tls = _report(
        "tls",
        status="skipped",
        findings=[_finding("tls_not_used", "medium")],
    )
    http = _report(
        "http",
        findings=[
            _finding("http_not_https", "high"),
            _finding("http_insecure_redirect", "medium"),
        ],
    )
    risk = assess_risk(_base_input(tls=tls, http=http))

    tls_points = sum(f.contribution for f in risk.factors if f.category == "tls")
    http_points = sum(f.contribution for f in risk.factors if f.category == "http")
    assert tls_points == 15
    assert http_points == 0
    assert risk.score == 15


def test_partial_coverage_prevents_low_band() -> None:
    risk = assess_risk(
        _base_input(
            intel=_report("intel", status="skipped", error="disabled"),
        )
    )

    assert risk.score is None
    assert risk.band == "insufficient_evidence"
    assert risk.confidence.covered_weight == 65


def test_strong_positive_evidence_is_scored_even_with_low_coverage() -> None:
    risk = assess_risk(
        AssessmentInput(
            url=_report("url", status="unknown"),
            tls=_report("tls", status="unknown"),
            http=_report("http", status="unknown"),
            intel=_intel_match(),
            brand=None,
            redirect_chain=(),
            scanner_status="failed",
        )
    )

    assert risk.score == 35
    assert risk.band == "guarded"
    assert risk.incomplete is True
    assert risk.confidence.covered_weight == 35


def test_maximum_contributions_reach_100_and_high_band() -> None:
    risk = assess_risk(
        AssessmentInput(
            url=_report("url", findings=[_finding("url_obfuscation", "critical")]),
            tls=_report("tls", findings=[_finding("tls_certificate_expired", "critical")]),
            http=_report("http", findings=[_finding("csp_missing", "critical")]),
            intel=_intel_match(),
            brand=BrandAssessment(status="match", brand="Example Bank"),
            redirect_chain=(
                "https://example.com/",
                "https://a.example.com/",
                "https://b.example.com/",
                "https://c.example.com/",
                "https://d.example.com/",
                "https://e.example.com/",
            ),
            scanner_status="complete",
        )
    )

    assert risk.score == 100
    assert risk.band == "high"
    assert risk.incomplete is False


def test_conflicting_sources_remain_visible() -> None:
    risk = assess_risk(
        _base_input(
            intel=_intel_match(),
            brand=BrandAssessment(status="no_match"),
        )
    )

    assert risk.score == 35
    assert "intel_confirmed_match" in risk.reason_codes
    assert "brand_no_impersonation" in risk.reason_codes


def test_golden_case_is_deterministic() -> None:
    risk = assess_risk(
        _base_input(
            url=_report("url", findings=[_finding("url_obfuscation", "medium")]),
            tls=_report("tls", findings=[_finding("tls_certificate_expiring", "medium")]),
            http=_report("http", findings=[_finding("hsts_missing", "medium")]),
            redirect_chain=("https://example.com/", "http://other.example.net/"),
        )
    )

    assert risk.score == 26
    assert risk.band == "guarded"
    assert risk.likelihood.score == 0.2
    assert risk.likelihood.band == "guarded"
    assert risk.posture.score == 56
    assert risk.posture.grade == "F"
    assert [p.points for p in risk.posture.penalties] == [24, 20]
    assert risk.confidence.covered_weight == 100
    assert risk.policy.version == "m7-2026-11-09.2"
    assert risk.reason_codes == [
        "intel_no_match",
        "url_finding_url_obfuscation",
        "brand_no_impersonation",
        "redirect_chain_length",
        "redirect_cross_domain",
        "redirect_http_hop",
        "tls_finding_tls_certificate_expiring",
        "http_finding_hsts_missing",
        "ml_probability_unavailable",
    ]

    again = assess_risk(
        _base_input(
            url=_report("url", findings=[_finding("url_obfuscation", "medium")]),
            tls=_report("tls", findings=[_finding("tls_certificate_expiring", "medium")]),
            http=_report("http", findings=[_finding("hsts_missing", "medium")]),
            redirect_chain=("https://example.com/", "http://other.example.net/"),
        )
    )
    assert again.model_dump() == risk.model_dump()


def test_explanation_uses_positive_factors() -> None:
    risk = assess_risk(_base_input(intel=_intel_match()))
    explanation = build_explanation(risk)

    assert explanation.summary == risk.verdict
    assert explanation.top_factors[0].feature == "intel_confirmed_match"
    assert explanation.top_factors[0].contribution == 35.0


def test_malformed_inputs_are_rejected_safely() -> None:
    with pytest.raises(AssessmentInputError, match="redirect_chain"):
        _base_input(redirect_chain=(None,))  # type: ignore[arg-type]
    with pytest.raises(AssessmentInputError, match="engine"):
        _base_input(url=_report("tls"))


def test_policy_rejects_invalid_weights_and_bands() -> None:
    with pytest.raises(ValueError, match="sum to 100"):
        RiskPolicy(weights={**DEFAULT_POLICY.weights, "intel": 34})
    with pytest.raises(ValueError, match="contiguous"):
        RiskPolicy(bands=(("low", 0, 20), ("guarded", 22, 39)))
