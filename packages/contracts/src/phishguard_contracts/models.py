"""Pydantic mirror of packages/contracts/schemas/*.schema.json.

These models are the Python runtime truth for validation. They MUST stay in
sync with the JSON Schema files; `services/*/tests/test_contract_parity.py`
enforces that by validating shared fixtures against both.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .enums import (
    EngineName,
    EngineStatus,
    ErrorCode,
    ReportCategory,
    ReportStatus,
    RiskBand,
    ScanStatus,
    Severity,
)

LabelKey = Literal["0", "1"]
LabelValue = Literal["phishing", "legitimate"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Finding(StrictModel):
    id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=256)
    severity: Severity
    detail: str | None = Field(default=None, max_length=4096)
    evidence_ref: str | None = None


class EngineReport(StrictModel):
    engine: EngineName
    status: EngineStatus
    findings: list[Finding] = Field(default_factory=list, max_length=100)
    evidence: dict[str, Any] = Field(default_factory=dict)
    source: str = Field(min_length=1, max_length=256)
    duration_ms: float = Field(ge=0)
    error: str | None = Field(default=None, max_length=1024)


class Engines(StrictModel):
    """All six engines are always present so a missing verdict is explicit."""

    ml: EngineReport
    url: EngineReport
    tls: EngineReport
    http: EngineReport
    intel: EngineReport
    community: EngineReport


class ScoreContribution(StrictModel):
    engine: EngineName
    weight: float = Field(ge=0, le=1)
    value: float = Field(ge=0, le=1)
    note: str | None = Field(default=None, max_length=512)


class LikelihoodScore(StrictModel):
    score: float = Field(ge=0, le=1)
    band: Literal["low", "guarded", "suspicious", "high", "critical"]
    contributions: list[ScoreContribution] = Field(default_factory=list)


class PosturePenalty(StrictModel):
    id: str = Field(max_length=128)
    points: float = Field(ge=0, le=100)
    note: str | None = Field(default=None, max_length=512)


class PostureScore(StrictModel):
    score: float = Field(ge=0, le=100)
    grade: Literal["A", "B", "C", "D", "F", "unknown"]
    status: EngineStatus
    penalties: list[PosturePenalty] = Field(default_factory=list)


class ConfidenceScore(StrictModel):
    score: float = Field(ge=0, le=1)
    engines_ok: int = Field(ge=0, le=6)
    engines_total: int = Field(ge=1, le=6)
    covered_weight: int = Field(ge=0, le=100)
    total_weight: int = Field(ge=1, le=100)
    incomplete: bool
    missing_evidence: list[str] = Field(default_factory=list, max_length=20)
    notes: list[str] = Field(default_factory=list, max_length=20)


RiskFactorCategory = Literal["intel", "url", "brand", "redirect", "tls", "http", "ml"]
RiskFactorStatus = Literal["applied", "evaluated", "no_match", "unavailable", "error"]


class RiskFactor(StrictModel):
    reason_code: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z0-9_.:-]+$",
    )
    category: RiskFactorCategory
    source: EngineName
    observed: float | str | bool | None = None
    contribution: int = Field(ge=0, le=100)
    max_contribution: int = Field(ge=0, le=100)
    direction: Literal["increases_risk", "decreases_risk", "informational"]
    severity: Severity
    explanation: str = Field(min_length=1, max_length=512)
    evidence_ref: str | None = None
    status: RiskFactorStatus


class RiskWeights(StrictModel):
    intel: int = Field(ge=0, le=100)
    url: int = Field(ge=0, le=100)
    brand: int = Field(ge=0, le=100)
    redirect: int = Field(ge=0, le=100)
    tls: int = Field(ge=0, le=100)
    http: int = Field(ge=0, le=100)

    @model_validator(mode="after")
    def _weights_sum_to_100(self) -> RiskWeights:
        if self.intel + self.url + self.brand + self.redirect + self.tls + self.http != 100:
            raise ValueError("risk weights must sum to 100")
        return self


class RiskBandRange(StrictModel):
    band: Literal["low", "guarded", "suspicious", "high"]
    min_score: int = Field(ge=0, le=100)
    max_score: int = Field(ge=0, le=100)

    @model_validator(mode="after")
    def _ordered_range(self) -> RiskBandRange:
        if self.min_score > self.max_score:
            raise ValueError("min_score must not exceed max_score")
        return self


class RiskPolicyMetadata(StrictModel):
    version: str = Field(min_length=1, max_length=64)
    calibrated: bool
    weights: RiskWeights
    bands: list[RiskBandRange] = Field(min_length=1, max_length=8)
    min_coverage_for_score: float = Field(ge=0, le=1)
    min_coverage_for_low: float = Field(ge=0, le=1)
    notes: list[str] = Field(default_factory=list, max_length=20)


class ModelProbability(StrictModel):
    probability_phishing: float = Field(ge=0, le=1)
    label: Literal["phishing", "legitimate", "unknown"]
    status: Literal["ok", "partial", "unknown"]
    model_version: str | None = Field(default=None, max_length=64)
    calibrated: bool
    used_in_risk_score: Literal[False] = False
    source: str = Field(min_length=1, max_length=256)


class RiskAssessment(StrictModel):
    score: int | None = Field(default=None, ge=0, le=100)
    band: RiskBand
    verdict: str = Field(min_length=1, max_length=512)
    incomplete: bool
    likelihood: LikelihoodScore
    posture: PostureScore
    confidence: ConfidenceScore
    factors: list[RiskFactor] = Field(default_factory=list, max_length=100)
    reason_codes: list[str] = Field(default_factory=list, max_length=100)
    model_probability: ModelProbability | None = None
    policy: RiskPolicyMetadata


class ExplanationFactor(StrictModel):
    feature: str = Field(max_length=128)
    value: float | str | bool | None = None
    contribution: float | None = None
    direction: Literal["increases_risk", "decreases_risk", "informational"]
    source: EngineName


class Explanation(StrictModel):
    top_factors: list[ExplanationFactor] = Field(default_factory=list, max_length=20)
    summary: str = Field(max_length=1024)


class ScanOptions(StrictModel):
    include_intel: bool = True
    include_ct: bool = False
    timeout_ms: int = Field(default=8000, ge=1000, le=15000)


class ScanRequest(StrictModel):
    url: str = Field(min_length=8, max_length=2048)
    options: ScanOptions = Field(default_factory=ScanOptions)

    @field_validator("url")
    @classmethod
    def _scheme(cls, value: str) -> str:
        if not value.lower().startswith(("http://", "https://")):
            raise ValueError("url scheme must be http or https")
        return value


class ScanAccepted(StrictModel):
    scan_id: str
    status: Literal["queued", "running"]
    poll_after_ms: int = Field(ge=100, le=10000)


class ScanResult(StrictModel):
    scan_id: str
    url: str = Field(max_length=2048)
    normalized_url: str = Field(max_length=2048)
    status: ScanStatus
    created_at: str
    completed_at: str | None = None
    duration_ms: float | None = Field(default=None, ge=0)
    risk: RiskAssessment | None = None
    engines: Engines
    explanation: Explanation | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _terminal_has_assessment(self) -> ScanResult:
        if (
            self.status in ("complete", "partial")
            and (self.risk is None or self.explanation is None)
        ):
            raise ValueError("complete/partial scans require risk and explanation")
        return self


class ErrorBody(StrictModel):
    code: ErrorCode
    message: str = Field(min_length=1, max_length=1024)
    request_id: str | None = Field(default=None, max_length=128)
    details: dict[str, Any] | None = None


class ErrorResponse(StrictModel):
    error: ErrorBody


class ModelMetrics(StrictModel):
    accuracy: float | None = Field(default=None, ge=0, le=1)
    precision: float | None = Field(default=None, ge=0, le=1)
    recall: float | None = Field(default=None, ge=0, le=1)
    f1: float | None = Field(default=None, ge=0, le=1)
    roc_auc: float | None = Field(default=None, ge=0, le=1)
    pr_auc: float | None = Field(default=None, ge=0, le=1)


class ModelMetadata(StrictModel):
    name: str = Field(max_length=128)
    version: str = Field(max_length=64)
    trained_at: str | None = None
    dataset: str | None = Field(default=None, max_length=256)
    feature_contract_version: str = Field(max_length=64)
    label_map: dict[LabelKey, LabelValue] | None = None
    metrics: ModelMetrics | None = None
    artifact_sha256: str | None = Field(default=None, pattern="^[0-9a-f]{64}$")


class Contribution(StrictModel):
    feature: str = Field(max_length=128)
    value: float | str | bool | None = None
    shap: float


class PredictRequest(StrictModel):
    features: dict[str, float | bool | str] = Field(min_length=1, max_length=128)
    explain: bool = True
    model_version: str | None = None


class PredictResponse(StrictModel):
    label: Literal["phishing", "legitimate", "unknown"]
    probability_phishing: float = Field(ge=0, le=1)
    contributions: list[Contribution] = Field(default_factory=list, max_length=64)
    missing_features: list[str] = Field(default_factory=list, max_length=128)
    status: Literal["ok", "partial", "unknown"]
    model: ModelMetadata


class FeatureContractEntry(StrictModel):
    name: str = Field(min_length=1, max_length=128)
    dataset_column: str = Field(min_length=1, max_length=128)
    dtype: Literal["number", "integer", "boolean", "category"]
    required: bool
    live_source: Literal["url", "tls", "http", "intel", "derived", "dataset_only"]
    default_policy: Literal["reject", "unknown", "neutral"]
    notes: str | None = Field(default=None, max_length=512)


class DatasetInfo(StrictModel):
    name: str | None = None
    rows: int | None = Field(default=None, ge=0)
    feature_count: int | None = Field(default=None, ge=0)
    class_counts: dict[str, int] | None = None


class FeatureContract(StrictModel):
    version: str = Field(max_length=64)
    model_version: str = Field(max_length=64)
    dataset: DatasetInfo | None = None
    label_map: dict[LabelKey, LabelValue]
    features: list[FeatureContractEntry] = Field(min_length=1)

    @field_validator("label_map")
    @classmethod
    def _both_labels(cls, value: dict[LabelKey, LabelValue]) -> dict[LabelKey, LabelValue]:
        if set(value) != {"0", "1"}:
            raise ValueError("label_map must define both '0' and '1'")
        if value["0"] != "phishing" or value["1"] != "legitimate":
            raise ValueError("label_map must be {0: phishing, 1: legitimate}")
        return value


class CreateReportRequest(StrictModel):
    url: str = Field(min_length=8, max_length=2048)
    category: ReportCategory
    description: str = Field(min_length=10, max_length=2000)
    evidence: dict[str, Any] | None = None


class Report(StrictModel):
    id: str
    url: str = Field(max_length=2048)
    category: ReportCategory
    description: str | None = Field(default=None, max_length=2000)
    status: ReportStatus
    created_at: str
    reporter_id: str | None = None
    vote_count: int


#: Maps a contract name to its model, used by the parity tests.
SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "scan-request": ScanRequest,
    "scan-accepted": ScanAccepted,
    "scan-result": ScanResult,
    "error": ErrorResponse,
    "ml-predict-request": PredictRequest,
    "ml-predict-response": PredictResponse,
    "report-create-request": CreateReportRequest,
    "report": Report,
}
