"""Deterministic TLS assessment for PHISHGUARD M6.

The scanner owns the network connection and certificate verification. This
module only interprets the TLS evidence it returns. It never performs I/O and
never turns missing evidence into a clean result.
"""

from __future__ import annotations

import ssl
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse, urlunparse

TLS_ENGINE_SOURCE = "phishguard-tls@0.1.0"

WEAK_PROTOCOLS = frozenset({"SSLV2", "SSLV3", "TLSV1", "TLSV1.0", "TLSV1.1"})
EXPIRING_SOON_DAYS = 30
EXPIRING_CRITICAL_DAYS = 14
WEAK_CIPHER_BITS = 128


@dataclass(frozen=True)
class TLSAssessment:
    status: str
    findings: tuple[dict[str, Any], ...] = ()
    evidence: dict[str, Any] = field(default_factory=dict)
    source: str = TLS_ENGINE_SOURCE
    error: str | None = None


def _sanitize_url(url: str) -> str:
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        netloc = host
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"
        return urlunparse((parsed.scheme, netloc, parsed.path or "/", "", "", ""))
    except ValueError:
        return url.split("?", 1)[0].split("#", 1)[0]


def _finding(
    rule_id: str,
    title: str,
    severity: str,
    detail: str,
    evidence_ref: str | None = None,
) -> dict[str, Any]:
    return {
        "id": rule_id,
        "title": title,
        "severity": severity,
        "detail": detail[:4096],
        "evidence_ref": evidence_ref,
    }


def _cert_time(value: Any) -> float | None:
    if not isinstance(value, str):
        return None
    try:
        return float(ssl.cert_time_to_seconds(value))
    except (ValueError, OverflowError):
        return None


def _name(value: Any) -> str | None:
    if not isinstance(value, (list, tuple)):
        return None
    for rdn in value:
        if not isinstance(rdn, (list, tuple)):
            continue
        for key, item in rdn:
            if key == "commonName" and item:
                return str(item)
    return None


def _certificate_evidence(certificate: Any) -> dict[str, Any]:
    if not isinstance(certificate, dict):
        return {}

    not_before = certificate.get("notBefore")
    not_after = certificate.get("notAfter")
    not_before_epoch = _cert_time(not_before)
    not_after_epoch = _cert_time(not_after)
    now = time.time()

    return {
        "subject": _name(certificate.get("subject")),
        "issuer": _name(certificate.get("issuer")),
        "not_before": not_before,
        "not_after": not_after,
        "days_until_expiry": (
            round((not_after_epoch - now) / 86_400, 2)
            if not_after_epoch is not None
            else None
        ),
        "subject_alt_name_count": len(certificate.get("subjectAltName") or []),
        "serial_number": certificate.get("serialNumber"),
        "version": certificate.get("version"),
        "_not_before_epoch": not_before_epoch,
        "_not_after_epoch": not_after_epoch,
    }


def assess_tls(
    final_url: str,
    tls_information: dict[str, Any] | None,
    *,
    scan_error: str | None = None,
    redirect_chain: list[str] | None = None,
) -> TLSAssessment:
    """Assess TLS evidence captured by the scanner.

    Status semantics:
    - ``ok``: TLS was assessed (findings may still be critical).
    - ``partial``: TLS evidence exists but is incomplete.
    - ``skipped``: the final URL is not HTTPS.
    - ``unknown``: no usable TLS evidence was produced.
    """
    scheme = urlparse(final_url).scheme.lower()
    safe_final_url = _sanitize_url(final_url)
    chain = [_sanitize_url(hop) for hop in (redirect_chain or [])]

    if scheme != "https":
        return TLSAssessment(
            status="skipped",
            findings=(
                _finding(
                    "tls_not_used",
                    "TLS is not used",
                    "medium",
                    "The final URL uses HTTP, so transport encryption cannot be assessed.",
                    "tls.final_url",
                ),
            ),
            evidence={
                "final_url": safe_final_url,
                "reason": "not_https",
                "redirect_chain": chain,
            },
            error="TLS is not applicable to an HTTP URL.",
        )

    if not tls_information:
        message = scan_error or "No TLS evidence was captured for the HTTPS target."
        return TLSAssessment(
            status="unknown",
            evidence={
                "final_url": safe_final_url,
                "reason": "tls_unavailable",
                "redirect_chain": chain,
            },
            error=message[:1024],
        )

    verified = bool(tls_information.get("verified"))
    protocol = tls_information.get("protocol")
    cipher = tls_information.get("cipher")
    certificate = tls_information.get("certificate")
    cert_evidence = _certificate_evidence(certificate)

    evidence: dict[str, Any] = {
        "final_url": safe_final_url,
        "verified": verified,
        "protocol": protocol,
        "cipher": cipher,
        "alpn": tls_information.get("alpn"),
        "server_hostname": tls_information.get("server_hostname"),
        "certificate": {
            key: value
            for key, value in cert_evidence.items()
            if not key.startswith("_")
        },
        "redirect_chain": chain,
    }
    if tls_information.get("error"):
        evidence["tls_error"] = tls_information["error"]

    findings: list[dict[str, Any]] = []
    errors: list[str] = []

    if not verified:
        findings.append(
            _finding(
                "tls_certificate_untrusted",
                "TLS certificate is not trusted",
                "critical",
                "The scanner could not verify the target certificate chain.",
                "tls.verified",
            )
        )
        errors.append(str(tls_information.get("error") or "certificate verification failed"))

    protocol_name = str(protocol or "").upper()
    if protocol_name and protocol_name in WEAK_PROTOCOLS:
        findings.append(
            _finding(
                "tls_weak_protocol",
                "Obsolete TLS protocol",
                "high",
                f"The target negotiated {protocol}, which is no longer considered secure.",
                "tls.protocol",
            )
        )
    elif not protocol_name:
        errors.append("TLS protocol version was not reported")

    if isinstance(cipher, dict):
        bits = cipher.get("bits")
        if isinstance(bits, int) and bits < WEAK_CIPHER_BITS:
            findings.append(
                _finding(
                    "tls_weak_cipher",
                    "Weak TLS cipher",
                    "high",
                    f"The negotiated cipher uses only {bits} bits.",
                    "tls.cipher",
                )
            )
    elif cipher is not None:
        errors.append("TLS cipher details were malformed")

    not_before = cert_evidence.get("_not_before_epoch")
    not_after = cert_evidence.get("_not_after_epoch")
    now = time.time()

    if not_before is not None and not_before > now:
        findings.append(
            _finding(
                "tls_certificate_not_yet_valid",
                "TLS certificate is not yet valid",
                "high",
                f"The certificate becomes valid at {cert_evidence.get('not_before')}.",
                "tls.certificate.notBefore",
            )
        )

    if not_after is not None:
        if not_after <= now:
            findings.append(
                _finding(
                    "tls_certificate_expired",
                    "TLS certificate has expired",
                    "critical",
                    f"The certificate expired at {cert_evidence.get('not_after')}.",
                    "tls.certificate.notAfter",
                )
            )
        else:
            days = (not_after - now) / 86_400
            if days <= EXPIRING_CRITICAL_DAYS:
                findings.append(
                    _finding(
                        "tls_certificate_expiring",
                        "TLS certificate expires very soon",
                        "high",
                        f"The certificate expires in {days:.1f} days.",
                        "tls.certificate.notAfter",
                    )
                )
            elif days <= EXPIRING_SOON_DAYS:
                findings.append(
                    _finding(
                        "tls_certificate_expiring",
                        "TLS certificate expires soon",
                        "medium",
                        f"The certificate expires in {days:.1f} days.",
                        "tls.certificate.notAfter",
                    )
                )
    elif verified:
        errors.append("Certificate validity dates were not reported")

    if verified and not cert_evidence:
        errors.append("Certificate details were not reported")

    status = "ok"
    error: str | None = None
    if errors:
        status = "partial" if findings else "unknown"
        error = "; ".join(errors)[:1024]

    return TLSAssessment(
        status=status,
        findings=tuple(findings),
        evidence=evidence,
        error=error,
    )
