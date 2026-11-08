from typing import Literal, get_args

ScanStatus = Literal["queued", "running", "complete", "partial", "failed"]
EngineStatus = Literal["ok", "partial", "skipped", "unknown", "error"]
Severity = Literal["info", "low", "medium", "high", "critical"]
RiskBand = Literal[
    "low",
    "guarded",
    "suspicious",
    "high",
    "critical",
    "insufficient_evidence",
]
EngineName = Literal["ml", "url", "tls", "http", "intel", "community"]
ErrorCode = Literal[
    "invalid_request",
    "invalid_url",
    "blocked_target",
    "rate_limited",
    "not_found",
    "unauthorized",
    "payload_too_large",
    "upstream_unavailable",
    "timeout",
    "internal",
]
ReportCategory = Literal[
    "phishing",
    "malware",
    "scam",
    "credential_theft",
    "impersonation",
    "other",
]
ReportStatus = Literal["pending", "verified", "rejected"]

ENGINE_NAMES: tuple[str, ...] = get_args(EngineName)
SCAN_STATUSES: tuple[str, ...] = get_args(ScanStatus)
ENGINE_STATUSES: tuple[str, ...] = get_args(EngineStatus)

#: Statuses that mean "no usable verdict". Never render or score these as safe.
NON_SAFE_STATUSES: frozenset[str] = frozenset({"unknown", "error", "skipped", "partial"})


def is_usable_verdict(status: str) -> bool:
    """Only an explicit ``ok`` counts as a usable verdict."""
    return status == "ok"
