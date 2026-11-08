"""Deterministic, explainable risk assessment for PHISHGUARD M7.

This module combines existing engine evidence into one policy-versioned result.
It does not perform I/O, does not call the ML model, and does not reinterpret an
engine's upstream semantics. Missing evidence is reported as missing and never
converted into a safe or low-risk verdict by itself.

The weights and bands are provisional heuristics. They are not calibrated
probabilities and must not be presented as such.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

import tldextract
from phishguard_contracts import (
    ConfidenceScore,
    EngineReport,
    Explanation,
    ExplanationFactor,
    LikelihoodScore,
    ModelProbability,
    PosturePenalty,
    PostureScore,
    RiskAssessment,
    RiskBandRange,
    RiskFactor,
    RiskPolicyMetadata,
    RiskWeights,
    ScoreContribution,
)

RISK_POLICY_VERSION = "m7-2026-11-09.2"

RISK_CATEGORIES: tuple[str, ...] = ("intel", "url", "brand", "redirect", "tls", "http")
LIKELIHOOD_CATEGORIES: tuple[str, ...] = ("intel", "url", "brand", "redirect")
POSTURE_CATEGORIES: tuple[str, ...] = ("tls", "http")

DEFAULT_WEIGHTS: dict[str, int] = {
    "intel": 35,
    "url": 15,
    "brand": 15,
    "redirect": 10,
    "tls": 15,
    "http": 10,
}

DEFAULT_BANDS: tuple[tuple[str, int, int], ...] = (
    ("low", 0, 19),
    ("guarded", 20, 39),
    ("suspicious", 40, 69),
    ("high", 70, 100),
)

#: Minimum weighted coverage before a non-empty assessment is published.
DEFAULT_MIN_COVERAGE_FOR_SCORE = 0.5
#: A low band is only published when coverage is at least this high.
DEFAULT_MIN_COVERAGE_FOR_LOW = 0.75

URL_FINDING_POINTS = {"critical": 15, "high": 10, "medium": 5, "low": 2, "info": 0}
TLS_FINDING_POINTS = {"critical": 15, "high": 10, "medium": 6, "low": 3, "info": 0}
HTTP_FINDING_POINTS = {"critical": 10, "high": 8, "medium": 5, "low": 2, "info": 0}

TLS_SEVERITY_OVERRIDES = {"tls_not_used": "high"}
TLS_POINT_OVERRIDES = {"tls_not_used": 15}

#: Correlated transport signals are counted in one category only.
HTTP_SKIP_FINDINGS = frozenset({"http_not_https", "http_insecure_redirect"})

PROVIDER_USABLE = frozenset({"match", "no_match"})
PROVIDER_MATCH = "match"


class AssessmentInputError(ValueError):
    """Raised when an assessment input cannot be used safely."""


@dataclass(frozen=True)
class BrandAssessment:
    """Optional upstream brand-impersonation evidence.

    No brand engine exists in M7. Supplying this object is how a future engine
    can contribute without changing the assessment contract.
    """

    status: Literal["match", "no_match", "unavailable", "error"]
    brand: str | None = None
    reason: str | None = None
    evidence_ref: str | None = None

    def __post_init__(self) -> None:
        if self.status not in {"match", "no_match", "unavailable", "error"}:
            raise AssessmentInputError(f"unsupported brand status: {self.status!r}")


@dataclass(frozen=True)
class AssessmentInput:
    """Typed input contract for every M7 evidence source."""

    url: EngineReport
    tls: EngineReport
    http: EngineReport
    intel: EngineReport
    ml: EngineReport | None = None
    brand: BrandAssessment | None = None
    redirect_chain: tuple[str, ...] = ()
    scanner_status: str | None = None
    scanner_error: str | None = None

    def __post_init__(self) -> None:
        expected = (
            ("url", self.url),
            ("tls", self.tls),
            ("http", self.http),
            ("intel", self.intel),
        )
        for name, report in expected:
            if not isinstance(report, EngineReport):
                raise AssessmentInputError(f"{name} evidence must be an EngineReport")
            if report.engine != name:
                raise AssessmentInputError(
                    f"{name} evidence has engine={report.engine!r}"
                )
        if self.ml is not None:
            if not isinstance(self.ml, EngineReport):
                raise AssessmentInputError("ml evidence must be an EngineReport or None")
            if self.ml.engine != "ml":
                raise AssessmentInputError(f"ml evidence has engine={self.ml.engine!r}")
        if self.brand is not None and not isinstance(self.brand, BrandAssessment):
            raise AssessmentInputError("brand evidence must be a BrandAssessment or None")
        if self.scanner_status not in {None, "complete", "partial", "failed"}:
            raise AssessmentInputError(f"unsupported scanner status: {self.scanner_status!r}")
        if self.scanner_error is not None and not isinstance(self.scanner_error, str):
            raise AssessmentInputError("scanner_error must be a string or None")
        if not isinstance(self.redirect_chain, (list, tuple)):
            raise AssessmentInputError("redirect_chain must be a list or tuple of URLs")
        normalized: list[str] = []
        for hop in self.redirect_chain[:20]:
            if not isinstance(hop, str) or not hop:
                raise AssessmentInputError("redirect_chain entries must be non-empty strings")
            normalized.append(hop[:2048])
        object.__setattr__(self, "redirect_chain", tuple(normalized))


@dataclass(frozen=True)
class RiskPolicy:
    """Configurable, explicitly uncalibrated M7 scoring policy."""

    version: str = RISK_POLICY_VERSION
    weights: Mapping[str, int] = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    calibrated: bool = False
    bands: tuple[tuple[str, int, int], ...] = DEFAULT_BANDS
    min_coverage_for_score: float = DEFAULT_MIN_COVERAGE_FOR_SCORE
    min_coverage_for_low: float = DEFAULT_MIN_COVERAGE_FOR_LOW

    def __post_init__(self) -> None:
        if set(self.weights) != set(RISK_CATEGORIES):
            raise ValueError(f"risk weights must define exactly {RISK_CATEGORIES}")
        if any(
            not isinstance(value, int) or not 0 <= value <= 100
            for value in self.weights.values()
        ):
            raise ValueError("risk weights must be integers between 0 and 100")
        if sum(self.weights.values()) != 100:
            raise ValueError("risk weights must sum to 100")
        if not 0 <= self.min_coverage_for_score <= 1:
            raise ValueError("min_coverage_for_score must be between 0 and 1")
        if not 0 <= self.min_coverage_for_low <= 1:
            raise ValueError("min_coverage_for_low must be between 0 and 1")
        previous_max = -1
        for band, low, high in self.bands:
            if band not in {"low", "guarded", "suspicious", "high"}:
                raise ValueError(f"unsupported band: {band!r}")
            if low != previous_max + 1 or high < low:
                raise ValueError("risk bands must be contiguous from 0 to 100")
            previous_max = high
        if previous_max != 100:
            raise ValueError("risk bands must end at 100")


DEFAULT_POLICY = RiskPolicy()


def band_for_score(score: int, policy: RiskPolicy = DEFAULT_POLICY) -> str:
    """Return the display band for a 0-100 score."""
    if not isinstance(score, int) or not 0 <= score <= 100:
        raise ValueError("score must be an integer between 0 and 100")
    for band, low, high in policy.bands:
        if low <= score <= high:
            return band
    return "insufficient_evidence"


def likelihood_band(score: float) -> str:
    if score < 0.2:
        return "low"
    if score < 0.4:
        return "guarded"
    if score < 0.7:
        return "suspicious"
    if score < 0.85:
        return "high"
    return "critical"


def _reason_part(value: str) -> str:
    return re.sub(r"[^a-z0-9_.:-]+", "_", value.lower()).strip("_") or "unknown"


def _short(value: Any, limit: int = 512) -> str:
    return str(value)[:limit]


def _evidence(report: EngineReport) -> dict[str, Any]:
    return report.evidence if isinstance(report.evidence, dict) else {}


def _factor(
    *,
    reason_code: str,
    category: str,
    source: str,
    observed: float | str | bool | None,
    contribution: int,
    max_contribution: int,
    direction: str,
    severity: str,
    explanation: str,
    status: str,
    evidence_ref: str | None = None,
) -> RiskFactor:
    return RiskFactor(
        reason_code=reason_code,
        category=category,  # type: ignore[arg-type]
        source=source,  # type: ignore[arg-type]
        observed=observed,
        contribution=contribution,
        max_contribution=max_contribution,
        direction=direction,  # type: ignore[arg-type]
        severity=severity,  # type: ignore[arg-type]
        explanation=_short(explanation),
        evidence_ref=evidence_ref,
        status=status,  # type: ignore[arg-type]
    )


def _score_findings(
    report: EngineReport,
    *,
    category: str,
    source: str,
    points_by_severity: Mapping[str, int],
    cap: int,
    skip_ids: frozenset[str] = frozenset(),
    severity_overrides: Mapping[str, str] | None = None,
    point_overrides: Mapping[str, int] | None = None,
    findings_make_available: bool = False,
    no_findings_code: str,
    no_findings_explanation: str,
    unavailable_code: str,
) -> tuple[list[RiskFactor], int, float]:
    severity_overrides = severity_overrides or {}
    point_overrides = point_overrides or {}
    findings = [finding for finding in report.findings if finding.id not in skip_ids]
    factors: list[RiskFactor] = []
    remaining = cap
    applied = 0

    for finding in findings:
        severity = severity_overrides.get(finding.id, finding.severity)
        points = point_overrides.get(
            finding.id,
            points_by_severity.get(severity, 0),
        )
        awarded = max(0, min(points, remaining))
        remaining -= awarded
        applied += awarded
        factors.append(
            _factor(
                reason_code=f"{category}_finding_{_reason_part(finding.id)}",
                category=category,
                source=source,
                observed=finding.detail or finding.title,
                contribution=awarded,
                max_contribution=max(0, points),
                direction="increases_risk" if awarded else "informational",
                severity=severity,
                explanation=f"{finding.title}. {finding.detail or ''}".strip(),
                status="applied" if awarded else "evaluated",
                evidence_ref=finding.evidence_ref,
            )
        )

    if findings:
        if report.status == "partial":
            coverage = 0.5
        elif report.status == "ok" or findings_make_available:
            coverage = 1.0
        else:
            coverage = 0.0
        if coverage == 0.0:
            factors.append(
                _factor(
                    reason_code=unavailable_code,
                    category=category,
                    source=source,
                    observed=report.error or report.status,
                    contribution=0,
                    max_contribution=0,
                    direction="informational",
                    severity="info",
                    explanation="The engine produced findings but its status is not usable.",
                    status="unavailable",
                )
            )
        return factors, applied, coverage

    if report.status == "ok":
        factors.append(
            _factor(
                reason_code=no_findings_code,
                category=category,
                source=source,
                observed="no findings",
                contribution=0,
                max_contribution=0,
                direction="decreases_risk",
                severity="info",
                explanation=no_findings_explanation,
                status="evaluated",
            )
        )
        return factors, 0, 1.0

    if report.status == "partial":
        factors.append(
            _factor(
                reason_code=f"{category}_partial_coverage",
                category=category,
                source=source,
                observed=report.error or "partial",
                contribution=0,
                max_contribution=0,
                direction="informational",
                severity="info",
                explanation="The engine returned partial evidence; coverage is reduced.",
                status="unavailable",
            )
        )
        return factors, 0, 0.5

    factors.append(
        _factor(
            reason_code=unavailable_code,
            category=category,
            source=source,
            observed=report.error or report.status,
            contribution=0,
            max_contribution=0,
            direction="informational",
            severity="info",
            explanation="No usable evidence was returned by this engine.",
            status="error" if report.status == "error" else "unavailable",
        )
    )
    return factors, 0, 0.0


def _intel_assessment(report: EngineReport, weight: int) -> tuple[list[RiskFactor], int, float]:
    evidence = _evidence(report)
    statuses = evidence.get("provider_statuses")
    if not isinstance(statuses, dict):
        statuses = {}
    usable = [
        provider
        for provider, status in statuses.items()
        if isinstance(status, str) and status in PROVIDER_USABLE
    ]
    matches = [
        provider
        for provider, status in statuses.items()
        if isinstance(status, str) and status == PROVIDER_MATCH
    ]
    if not statuses:
        if report.status == "ok":
            coverage = 1.0
            if report.findings:
                matches = ["reported_match"]
            else:
                usable = ["reported_no_match"]
        elif report.status == "partial":
            coverage = 0.5
        else:
            coverage = 0.0
    else:
        coverage = len(usable) / len(statuses)

    factors: list[RiskFactor] = []
    if matches:
        severity = "high"
        for finding in report.findings:
            if finding.severity in {"critical", "high"}:
                severity = finding.severity
                break
        factors.append(
            _factor(
                reason_code="intel_confirmed_match",
                category="intel",
                source="intel",
                observed=", ".join(str(provider) for provider in matches),
                contribution=weight,
                max_contribution=weight,
                direction="increases_risk",
                severity=severity,
                explanation="At least one threat-intelligence provider reported a match.",
                status="applied",
                evidence_ref="intel.providers",
            )
        )
    elif usable:
        factors.append(
            _factor(
                reason_code="intel_no_match",
                category="intel",
                source="intel",
                observed=", ".join(str(provider) for provider in usable),
                contribution=0,
                max_contribution=0,
                direction="decreases_risk",
                severity="info",
                explanation="No provider reported a match. This is not proof of safety.",
                status="no_match",
                evidence_ref="intel.provider_statuses",
            )
        )
    else:
        factors.append(
            _factor(
                reason_code="intel_unavailable",
                category="intel",
                source="intel",
                observed=report.error or report.status,
                contribution=0,
                max_contribution=0,
                direction="informational",
                severity="info",
                explanation="No threat-intelligence provider returned a usable result.",
                status="error" if report.status == "error" else "unavailable",
                evidence_ref="intel.provider_statuses",
            )
        )

    if statuses and 0 < coverage < 1:
        factors.append(
            _factor(
                reason_code="intel_partial_coverage",
                category="intel",
                source="intel",
                observed=f"{len(usable)}/{len(statuses)} providers usable",
                contribution=0,
                max_contribution=0,
                direction="informational",
                severity="info",
                explanation="Only part of the configured threat-intelligence coverage was usable.",
                status="unavailable",
                evidence_ref="intel.provider_statuses",
            )
        )
    return factors, weight if matches else 0, coverage


def _registered_domain(host: str) -> str:
    extracted = tldextract.extract(host)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}".lower()
    return host.lower()


def _host(url: str) -> str:
    from urllib.parse import urlparse

    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _redirect_assessment(
    redirect_chain: Sequence[str],
    *,
    scanner_status: str | None,
    scanner_error: str | None,
    weight: int,
) -> tuple[list[RiskFactor], int, float]:
    if not redirect_chain:
        return (
            [
                _factor(
                    reason_code="redirect_unavailable",
                    category="redirect",
                    source="http",
                    observed="no redirect chain",
                    contribution=0,
                    max_contribution=0,
                    direction="informational",
                    severity="info",
                    explanation="No redirect chain was available for assessment.",
                    status="unavailable",
                )
            ],
            0,
            0.0,
        )

    if scanner_status == "failed" and len(redirect_chain) <= 1:
        return (
            [
                _factor(
                    reason_code="redirect_unavailable",
                    category="redirect",
                    source="http",
                    observed=scanner_error or "scanner failed",
                    contribution=0,
                    max_contribution=0,
                    direction="informational",
                    severity="info",
                    explanation="The scanner failed before redirect behavior could be assessed.",
                    status="unavailable",
                )
            ],
            0,
            0.0,
        )

    parsed_hosts = [_host(hop) for hop in redirect_chain]
    if any(not host for host in parsed_hosts):
        return (
            [
                _factor(
                    reason_code="redirect_malformed_evidence",
                    category="redirect",
                    source="http",
                    observed="redirect chain contains an invalid URL",
                    contribution=0,
                    max_contribution=0,
                    direction="informational",
                    severity="info",
                    explanation="Redirect evidence was malformed and was not scored.",
                    status="error",
                )
            ],
            0,
            0.0,
        )

    hops = max(0, len(redirect_chain) - 1)
    candidates: list[tuple[str, int, str, str]] = []
    error_text = (scanner_error or "").lower()
    if "redirect loop" in error_text:
        candidates.append(
            (
                "redirect_loop_detected",
                10,
                "high",
                "The scanner detected a redirect loop.",
            )
        )
    if hops >= 5:
        candidates.append(
            ("redirect_chain_length", 10, "high", f"The chain has {hops} redirect hops.")
        )
    elif hops >= 3:
        candidates.append(
            ("redirect_chain_length", 7, "medium", f"The chain has {hops} redirect hops.")
        )
    elif hops >= 1:
        candidates.append(
            ("redirect_chain_length", 4, "low", f"The chain has {hops} redirect hop(s).")
        )

    original_domain = _registered_domain(parsed_hosts[0])
    final_domain = _registered_domain(parsed_hosts[-1])
    if original_domain != final_domain:
        candidates.append(
            (
                "redirect_cross_domain",
                4,
                "medium",
                f"Redirects cross from {original_domain} to {final_domain}.",
            )
        )
    elif parsed_hosts[0] != parsed_hosts[-1]:
        candidates.append(
            (
                "redirect_host_change",
                2,
                "low",
                f"Redirects change host from {parsed_hosts[0]} to {parsed_hosts[-1]}.",
            )
        )

    if any(str(hop).lower().startswith("http://") for hop in redirect_chain):
        candidates.append(
            (
                "redirect_http_hop",
                4,
                "medium",
                "At least one redirect hop uses unencrypted HTTP.",
            )
        )

    factors: list[RiskFactor] = []
    remaining = weight
    applied = 0
    for reason_code, points, severity, explanation in candidates:
        awarded = max(0, min(points, remaining))
        remaining -= awarded
        applied += awarded
        if awarded == 0:
            continue
        factors.append(
            _factor(
                reason_code=reason_code,
                category="redirect",
                source="http",
                observed=hops,
                contribution=awarded,
                max_contribution=points,
                direction="increases_risk",
                severity=severity,
                explanation=explanation,
                status="applied",
                evidence_ref="transport.redirect_chain",
            )
        )

    if not factors:
        factors.append(
            _factor(
                reason_code="redirect_no_suspicious_behavior",
                category="redirect",
                source="http",
                observed="no redirects",
                contribution=0,
                max_contribution=0,
                direction="decreases_risk",
                severity="info",
                explanation="No suspicious redirect behavior was observed.",
                status="evaluated",
                evidence_ref="transport.redirect_chain",
            )
        )

    coverage = 0.5 if scanner_status == "failed" else 1.0
    return factors, applied, coverage


def _brand_assessment(
    brand: BrandAssessment | None,
    weight: int,
) -> tuple[list[RiskFactor], int, float]:
    if brand is None:
        return (
            [
                _factor(
                    reason_code="brand_evidence_unavailable",
                    category="brand",
                    source="url",
                    observed="no brand engine",
                    contribution=0,
                    max_contribution=0,
                    direction="informational",
                    severity="info",
                    explanation="Brand-impersonation evidence is not available in M7.",
                    status="unavailable",
                )
            ],
            0,
            0.0,
        )
    if brand.status == "match":
        return (
            [
                _factor(
                    reason_code="brand_impersonation_confirmed",
                    category="brand",
                    source="url",
                    observed=brand.brand or "brand match",
                    contribution=weight,
                    max_contribution=weight,
                    direction="increases_risk",
                    severity="high",
                    explanation="Upstream evidence confirms brand impersonation.",
                    status="applied",
                    evidence_ref=brand.evidence_ref,
                )
            ],
            weight,
            1.0,
        )
    if brand.status == "no_match":
        return (
            [
                _factor(
                    reason_code="brand_no_impersonation",
                    category="brand",
                    source="url",
                    observed=brand.brand or "no match",
                    contribution=0,
                    max_contribution=0,
                    direction="decreases_risk",
                    severity="info",
                    explanation=(
                        "Brand evidence did not report impersonation. "
                        "This is not proof of safety."
                    ),
                    status="no_match",
                    evidence_ref=brand.evidence_ref,
                )
            ],
            0,
            1.0,
        )
    return (
        [
            _factor(
                reason_code="brand_evidence_unavailable",
                category="brand",
                source="url",
                observed=brand.reason or brand.status,
                contribution=0,
                max_contribution=0,
                direction="informational",
                severity="info",
                explanation="Brand-impersonation evidence was unavailable.",
                status="error" if brand.status == "error" else "unavailable",
                evidence_ref=brand.evidence_ref,
            )
        ],
        0,
        0.0,
    )


def _model_probability(
    ml: EngineReport | None,
) -> tuple[ModelProbability | None, RiskFactor]:
    if ml is None:
        return (
            None,
            _factor(
                reason_code="ml_probability_unavailable",
                category="ml",
                source="ml",
                observed="no ML engine report",
                contribution=0,
                max_contribution=0,
                direction="informational",
                severity="info",
                explanation=(
                    "ML probability was not available and is not part of the heuristic score."
                ),
                status="unavailable",
            ),
        )

    evidence = _evidence(ml)
    probability = evidence.get("probability_phishing")
    if (
        isinstance(probability, (int, float))
        and not isinstance(probability, bool)
        and 0 <= float(probability) <= 1
    ):
        label = evidence.get("label")
        if label not in {"phishing", "legitimate", "unknown"}:
            label = "phishing" if float(probability) >= 0.5 else "legitimate"
        status = evidence.get("status")
        if status not in {"ok", "partial", "unknown"}:
            if ml.status == "ok":
                status = "ok"
            elif ml.status == "partial":
                status = "partial"
            else:
                status = "unknown"
        model_version = evidence.get("model_version")
        if not isinstance(model_version, str):
            model = evidence.get("model")
            model_version = model.get("version") if isinstance(model, dict) else None
        return (
            ModelProbability(
                probability_phishing=float(probability),
                label=label,
                status=status,
                model_version=model_version if isinstance(model_version, str) else None,
                calibrated=False,
                source=ml.source[:256],
            ),
            _factor(
                reason_code="ml_probability_informational",
                category="ml",
                source="ml",
                observed=float(probability),
                contribution=0,
                max_contribution=0,
                direction="informational",
                severity="info",
                explanation=(
                    "ML phishing probability is reported separately and is not included "
                    "in the heuristic risk score."
                ),
                status="evaluated",
                evidence_ref="ml.probability_phishing",
            ),
        )

    unavailable = ml.status in {"skipped", "unknown", "error"}
    return (
        None,
        _factor(
            reason_code=(
                "ml_probability_unavailable"
                if unavailable
                else "ml_probability_malformed"
            ),
            category="ml",
            source="ml",
            observed=str(probability)[:128] if probability is not None else "missing",
            contribution=0,
            max_contribution=0,
            direction="informational",
            severity="info",
            explanation=(
                "ML probability was unavailable and was not used."
                if unavailable
                else "ML probability was missing or malformed and was not used."
            ),
            status="unavailable" if unavailable else "error",
            evidence_ref="ml.probability_phishing",
        ),
    )


def _posture_score(
    factors: Sequence[RiskFactor],
    *,
    tls_points: int,
    http_points: int,
    tls_coverage: float,
    http_coverage: float,
    policy: RiskPolicy,
) -> PostureScore:
    covered = (
        policy.weights["tls"] * tls_coverage
        + policy.weights["http"] * http_coverage
    )
    if covered <= 0:
        return PostureScore(score=0, grade="unknown", status="unknown", penalties=[])

    posture_points = tls_points + http_points
    risk_percent = min(100, round(posture_points / covered * 100))
    score = 100 - risk_percent
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"
    status = "ok" if tls_coverage >= 1 and http_coverage >= 1 else "partial"

    penalties: list[PosturePenalty] = []
    for factor in factors:
        if factor.category not in POSTURE_CATEGORIES or factor.contribution <= 0:
            continue
        points = min(100, round(factor.contribution / covered * 100))
        penalties.append(
            PosturePenalty(
                id=factor.reason_code[:128],
                points=points,
                note=factor.explanation[:512],
            )
        )
    return PostureScore(score=score, grade=grade, status=status, penalties=penalties)


def _confidence_score(
    *,
    coverage: Mapping[str, float],
    policy: RiskPolicy,
    engines: Sequence[EngineReport],
) -> ConfidenceScore:
    covered_weight = round(
        sum(policy.weights[category] * coverage.get(category, 0.0) for category in RISK_CATEGORIES)
    )
    missing = [
        f"{category}: {round(coverage.get(category, 0.0) * 100)}% coverage"
        for category in RISK_CATEGORIES
        if coverage.get(category, 0.0) < 1.0
    ]
    engines_ok = sum(1 for report in engines if report.status == "ok")
    notes = [
        f"policy={policy.version}; calibrated={str(policy.calibrated).lower()}",
        "ML probability is reported separately and is not part of the risk score.",
    ]
    return ConfidenceScore(
        score=round(covered_weight / 100, 4),
        engines_ok=engines_ok,
        engines_total=6,
        covered_weight=covered_weight,
        total_weight=100,
        incomplete=covered_weight < 100,
        missing_evidence=missing[:20],
        notes=notes,
    )


def _verdict(band: str, covered_weight: int) -> str:
    if band == "insufficient_evidence":
        return "Insufficient evidence for a reliable risk score. Assessment is incomplete."
    prefix = {
        "low": "Low observed risk.",
        "guarded": "Guarded risk.",
        "suspicious": "Suspicious risk.",
        "high": "High risk.",
        "critical": "Critical risk.",
    }.get(band, "Risk assessment produced.")
    text = prefix
    if band == "low":
        text += " This is not a safety guarantee."
    if covered_weight < 100:
        text += f" Evidence coverage is {covered_weight}%."
    return text[:512]


def assess_risk(
    assessment_input: AssessmentInput,
    policy: RiskPolicy = DEFAULT_POLICY,
) -> RiskAssessment:
    """Assess one input deterministically. Identical inputs yield identical output."""
    intel_factors, intel_points, intel_coverage = _intel_assessment(
        assessment_input.intel, policy.weights["intel"]
    )
    url_factors, url_points, url_coverage = _score_findings(
        assessment_input.url,
        category="url",
        source="url",
        points_by_severity=URL_FINDING_POINTS,
        cap=policy.weights["url"],
        no_findings_code="url_no_suspicious_characteristics",
        no_findings_explanation="The URL engine reported no suspicious characteristics.",
        unavailable_code="url_unavailable",
    )
    brand_factors, brand_points, brand_coverage = _brand_assessment(
        assessment_input.brand, policy.weights["brand"]
    )
    redirect_factors, redirect_points, redirect_coverage = _redirect_assessment(
        assessment_input.redirect_chain,
        scanner_status=assessment_input.scanner_status,
        scanner_error=assessment_input.scanner_error,
        weight=policy.weights["redirect"],
    )
    tls_factors, tls_points, tls_coverage = _score_findings(
        assessment_input.tls,
        category="tls",
        source="tls",
        points_by_severity=TLS_FINDING_POINTS,
        cap=policy.weights["tls"],
        severity_overrides=TLS_SEVERITY_OVERRIDES,
        point_overrides=TLS_POINT_OVERRIDES,
        findings_make_available=True,
        no_findings_code="tls_no_findings",
        no_findings_explanation="No TLS or certificate weaknesses were reported.",
        unavailable_code="tls_unavailable",
    )
    http_factors, http_points, http_coverage = _score_findings(
        assessment_input.http,
        category="http",
        source="http",
        points_by_severity=HTTP_FINDING_POINTS,
        cap=policy.weights["http"],
        skip_ids=HTTP_SKIP_FINDINGS,
        no_findings_code="http_security_ok",
        no_findings_explanation="No HTTP security-configuration weaknesses were reported.",
        unavailable_code="http_unavailable",
    )
    model_probability, ml_factor = _model_probability(assessment_input.ml)

    factors = (
        intel_factors
        + url_factors
        + brand_factors
        + redirect_factors
        + tls_factors
        + http_factors
        + [ml_factor]
    )
    coverage = {
        "intel": intel_coverage,
        "url": url_coverage,
        "brand": brand_coverage,
        "redirect": redirect_coverage,
        "tls": tls_coverage,
        "http": http_coverage,
    }
    covered_weight = round(
        sum(policy.weights[category] * coverage[category] for category in RISK_CATEGORIES)
    )

    likelihood_points = intel_points + url_points + brand_points + redirect_points
    likelihood_max = sum(policy.weights[category] for category in LIKELIHOOD_CATEGORIES)
    likelihood_value = round(likelihood_points / likelihood_max, 4)
    contributions: list[ScoreContribution] = []
    category_points = {
        "intel": intel_points,
        "url": url_points,
        "brand": brand_points,
        "redirect": redirect_points,
    }
    for category in LIKELIHOOD_CATEGORIES:
        category_weight = policy.weights[category]
        category_coverage = coverage[category]
        if category_coverage <= 0:
            continue
        effective_weight = category_weight * category_coverage
        contribution_engine = (
            "url" if category == "brand" else "http" if category == "redirect" else category
        )
        contributions.append(
            ScoreContribution(
                engine=contribution_engine,  # type: ignore[arg-type]
                weight=round(effective_weight / likelihood_max, 4),
                value=round(category_points[category] / effective_weight, 4)
                if effective_weight
                else 0.0,
                note=f"{category} coverage={round(category_coverage * 100)}%",
            )
        )

    posture = _posture_score(
        factors,
        tls_points=tls_points,
        http_points=http_points,
        tls_coverage=tls_coverage,
        http_coverage=http_coverage,
        policy=policy,
    )
    ml_report = assessment_input.ml or EngineReport(
        engine="ml",
        status="unknown",
        findings=[],
        evidence={},
        source="not-implemented",
        duration_ms=0.0,
    )
    community_report = EngineReport(
        engine="community",
        status="skipped",
        findings=[],
        evidence={},
        source="not-implemented",
        duration_ms=0.0,
    )
    confidence = _confidence_score(
        coverage=coverage,
        policy=policy,
        engines=[
            ml_report,
            assessment_input.url,
            assessment_input.tls,
            assessment_input.http,
            assessment_input.intel,
            community_report,
        ],
    )

    raw_score = min(
        100,
        intel_points
        + url_points
        + brand_points
        + redirect_points
        + tls_points
        + http_points,
    )
    strong_positive = intel_points > 0 or brand_points > 0 or any(
        factor.contribution > 0 and factor.severity == "critical" for factor in factors
    )
    coverage_ratio = covered_weight / 100
    if coverage_ratio < policy.min_coverage_for_score and not strong_positive:
        score: int | None = None
        band = "insufficient_evidence"
    elif raw_score < 20 and coverage_ratio < policy.min_coverage_for_low:
        score = None
        band = "insufficient_evidence"
    else:
        score = raw_score
        band = band_for_score(raw_score, policy)

    reason_codes = list(dict.fromkeys(factor.reason_code for factor in factors))
    return RiskAssessment(
        score=score,
        band=band,  # type: ignore[arg-type]
        verdict=_verdict(band, covered_weight),
        incomplete=covered_weight < 100,
        likelihood=LikelihoodScore(
            score=likelihood_value,
            band=likelihood_band(likelihood_value),  # type: ignore[arg-type]
            contributions=contributions,
        ),
        posture=posture,
        confidence=confidence,
        factors=factors,
        reason_codes=reason_codes,
        model_probability=model_probability,
        policy=RiskPolicyMetadata(
            version=policy.version,
            calibrated=policy.calibrated,
            weights=RiskWeights(**dict(policy.weights)),
            bands=[
                RiskBandRange(band=band_name, min_score=low, max_score=high)  # type: ignore[arg-type]
                for band_name, low, high in policy.bands
            ],
            min_coverage_for_score=policy.min_coverage_for_score,
            min_coverage_for_low=policy.min_coverage_for_low,
            notes=[
                "Weights and bands are provisional heuristics, not calibrated probabilities.",
                "Brand-impersonation evidence is unavailable until a brand engine exists.",
            ],
        ),
    )


def build_explanation(assessment: RiskAssessment) -> Explanation:
    """Build the user-facing explanation from the assessment factors."""
    positive = sorted(
        (factor for factor in assessment.factors if factor.contribution > 0),
        key=lambda factor: (-factor.contribution, factor.reason_code),
    )
    selected = positive[:10]
    if not selected:
        selected = [
            factor
            for factor in assessment.factors
            if factor.status in {"no_match", "unavailable", "error"}
        ][:5]
    top_factors = [
        ExplanationFactor(
            feature=factor.reason_code,
            value=factor.observed,
            contribution=float(factor.contribution),
            direction=factor.direction,
            source=factor.source,
        )
        for factor in selected
    ]
    return Explanation(top_factors=top_factors, summary=assessment.verdict[:1024])
