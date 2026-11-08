"""Deterministic HTTP security-header assessment for PHISHGUARD M6.

This module interprets response headers captured by the scanner. It performs no
network I/O, never includes response bodies, and never treats a missing header
as a clean result.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse, urlunparse

HTTP_ENGINE_SOURCE = "phishguard-http@0.1.0"

HSTS_MIN_MAX_AGE = 15_552_000  # 180 days
MAX_EVIDENCE_HEADER_LENGTH = 512

SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)


@dataclass(frozen=True)
class HTTPAssessment:
    status: str
    findings: tuple[dict[str, Any], ...] = ()
    evidence: dict[str, Any] = field(default_factory=dict)
    source: str = HTTP_ENGINE_SOURCE
    error: str | None = None


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


def sanitize_url_for_evidence(url: str) -> str:
    """Drop credentials, query string and fragment from evidence URLs."""
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


def _normalized_headers(headers: dict[str, str] | None) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for key, value in (headers or {}).items():
        lower = key.lower()
        if lower in normalized:
            normalized[lower] = f"{normalized[lower]}, {value}"
        else:
            normalized[lower] = value
    return normalized


def _short(value: str | None) -> str | None:
    if value is None:
        return None
    return value[:MAX_EVIDENCE_HEADER_LENGTH]


def _cookie_flags(cookie: str) -> dict[str, str | bool]:
    parts = [part.strip() for part in cookie.split(";")]
    attributes: dict[str, str | bool] = {}
    for part in parts[1:]:
        if not part:
            continue
        name, _, value = part.partition("=")
        attributes[name.strip().lower()] = value.strip().lower() if value else True
    return attributes


def assess_http_security(
    final_url: str,
    response_headers: dict[str, str] | None,
    *,
    http_status: int | None = None,
    set_cookie_headers: list[str] | None = None,
    redirect_chain: list[str] | None = None,
    scan_error: str | None = None,
) -> HTTPAssessment:
    """Assess HTTP transport and security headers from scanner evidence."""
    parsed = urlparse(final_url)
    scheme = parsed.scheme.lower()
    sanitized_url = sanitize_url_for_evidence(final_url)
    sanitized_chain = [sanitize_url_for_evidence(hop) for hop in (redirect_chain or [])]

    if scheme not in {"http", "https"}:
        return HTTPAssessment(
            status="unknown",
            evidence={"final_url": sanitized_url, "reason": "unsupported_scheme"},
            error="HTTP assessment requires an http or https URL.",
        )

    headers = _normalized_headers(response_headers)
    if not headers:
        message = scan_error or "No HTTP response headers were captured."
        return HTTPAssessment(
            status="unknown",
            evidence={
                "final_url": sanitized_url,
                "reason": "no_response_headers",
                "redirect_chain": sanitized_chain,
            },
            error=message[:1024],
        )

    is_https = scheme == "https"
    hsts = headers.get("strict-transport-security")
    csp = headers.get("content-security-policy")
    xcto = headers.get("x-content-type-options")
    xfo = headers.get("x-frame-options")
    referrer = headers.get("referrer-policy")
    permissions = headers.get("permissions-policy")
    server = headers.get("server")
    powered_by = headers.get("x-powered-by")
    cookies = list(set_cookie_headers or [])

    findings: list[dict[str, Any]] = []

    if not is_https:
        findings.append(
            _finding(
                "http_not_https",
                "Page is served over HTTP",
                "high",
                "The final URL does not use TLS, so traffic can be modified in transit.",
                "http.final_url",
            )
        )

    for hop in sanitized_chain:
        if hop.lower().startswith("http://"):
            findings.append(
                _finding(
                    "http_insecure_redirect",
                    "Redirect chain uses HTTP",
                    "medium",
                    f"A redirect hop uses unencrypted HTTP: {hop}",
                    "http.redirect_chain",
                )
            )
            break

    if is_https:
        if not hsts:
            findings.append(
                _finding(
                    "hsts_missing",
                    "HSTS is missing",
                    "medium",
                    "Strict-Transport-Security is absent, so browsers may use HTTP later.",
                    "http.headers.strict-transport-security",
                )
            )
        else:
            max_age_match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age <= 0:
                    findings.append(
                        _finding(
                            "hsts_disabled",
                            "HSTS is disabled",
                            "high",
                            "Strict-Transport-Security has max-age=0.",
                            "http.headers.strict-transport-security",
                        )
                    )
                elif max_age < HSTS_MIN_MAX_AGE:
                    findings.append(
                        _finding(
                            "hsts_short_max_age",
                            "HSTS max-age is short",
                            "low",
                            f"HSTS max-age is {max_age} seconds; 180 days or more is recommended.",
                            "http.headers.strict-transport-security",
                        )
                    )
            if "includesubdomains" not in hsts.lower():
                findings.append(
                    _finding(
                        "hsts_no_subdomains",
                        "HSTS does not cover subdomains",
                        "info",
                        "Strict-Transport-Security does not include includeSubDomains.",
                        "http.headers.strict-transport-security",
                    )
                )

    if not csp:
        findings.append(
            _finding(
                "csp_missing",
                "Content-Security-Policy is missing",
                "medium",
                "No CSP restricts script and resource origins.",
                "http.headers.content-security-policy",
            )
        )
    else:
        csp_lower = csp.lower()
        if "'unsafe-inline'" in csp_lower:
            findings.append(
                _finding(
                    "csp_unsafe_inline",
                    "CSP allows unsafe inline content",
                    "low",
                    "Content-Security-Policy contains 'unsafe-inline'.",
                    "http.headers.content-security-policy",
                )
            )
        if "'unsafe-eval'" in csp_lower:
            findings.append(
                _finding(
                    "csp_unsafe_eval",
                    "CSP allows unsafe eval",
                    "low",
                    "Content-Security-Policy contains 'unsafe-eval'.",
                    "http.headers.content-security-policy",
                )
            )

    if not xcto or xcto.strip().lower() != "nosniff":
        findings.append(
            _finding(
                "x_content_type_options_missing",
                "X-Content-Type-Options is missing or invalid",
                "low",
                "The response does not set X-Content-Type-Options: nosniff.",
                "http.headers.x-content-type-options",
            )
        )

    csp_has_frame_ancestors = bool(csp and "frame-ancestors" in csp.lower())
    if not xfo and not csp_has_frame_ancestors:
        findings.append(
            _finding(
                "x_frame_options_missing",
                "Clickjacking protection is missing",
                "low",
                "Neither X-Frame-Options nor CSP frame-ancestors is present.",
                "http.headers.x-frame-options",
            )
        )

    if not referrer:
        findings.append(
            _finding(
                "referrer_policy_missing",
                "Referrer-Policy is missing",
                "info",
                "The response does not restrict referrer information.",
                "http.headers.referrer-policy",
            )
        )

    if not permissions:
        findings.append(
            _finding(
                "permissions_policy_missing",
                "Permissions-Policy is missing",
                "info",
                "The response does not restrict powerful browser features.",
                "http.headers.permissions-policy",
            )
        )

    if server and re.search(r"\d+\.\d+", server):
        findings.append(
            _finding(
                "server_version_disclosure",
                "Server version is disclosed",
                "info",
                "The Server header includes a version number.",
                "http.headers.server",
            )
        )
    if powered_by:
        findings.append(
            _finding(
                "powered_by_disclosure",
                "Technology stack is disclosed",
                "info",
                "The X-Powered-By header exposes framework information.",
                "http.headers.x-powered-by",
            )
        )

    cookie_summary = {
        "count": len(cookies),
        "missing_secure": 0,
        "missing_httponly": 0,
        "missing_samesite": 0,
        "samesite_none_without_secure": 0,
    }
    for cookie in cookies:
        attributes = _cookie_flags(cookie)
        secure = "secure" in attributes
        httponly = "httponly" in attributes
        samesite = attributes.get("samesite")

        if is_https and not secure:
            cookie_summary["missing_secure"] += 1
        if not httponly:
            cookie_summary["missing_httponly"] += 1
        if samesite is None:
            cookie_summary["missing_samesite"] += 1
        if samesite == "none" and not secure:
            cookie_summary["samesite_none_without_secure"] += 1

    if cookie_summary["missing_secure"]:
        findings.append(
            _finding(
                "cookie_missing_secure",
                "Cookies lack the Secure flag",
                "medium",
                f"{cookie_summary['missing_secure']} cookie(s) do not set Secure.",
                "http.set_cookie",
            )
        )
    if cookie_summary["missing_httponly"]:
        findings.append(
            _finding(
                "cookie_missing_httponly",
                "Cookies lack the HttpOnly flag",
                "low",
                f"{cookie_summary['missing_httponly']} cookie(s) do not set HttpOnly.",
                "http.set_cookie",
            )
        )
    if cookie_summary["missing_samesite"]:
        findings.append(
            _finding(
                "cookie_missing_samesite",
                "Cookies lack the SameSite attribute",
                "low",
                f"{cookie_summary['missing_samesite']} cookie(s) do not set SameSite.",
                "http.set_cookie",
            )
        )
    if cookie_summary["samesite_none_without_secure"]:
        findings.append(
            _finding(
                "cookie_samesite_none_without_secure",
                "SameSite=None cookie is not Secure",
                "high",
                "A cookie uses SameSite=None without the Secure flag.",
                "http.set_cookie",
            )
        )

    present_headers = [name for name in SECURITY_HEADERS if name in headers]
    missing_headers = [name for name in SECURITY_HEADERS if name not in headers]

    return HTTPAssessment(
        status="ok",
        findings=tuple(findings),
        evidence={
            "final_url": sanitized_url,
            "https": is_https,
            "http_status": http_status,
            "present_headers": present_headers,
            "missing_headers": missing_headers,
            "security_headers": {
                "strict_transport_security": _short(hsts),
                "content_security_policy": _short(csp),
                "x_content_type_options": _short(xcto),
                "x_frame_options": _short(xfo),
                "referrer_policy": _short(referrer),
                "permissions_policy": _short(permissions),
            },
            "server": _short(server),
            "x_powered_by": _short(powered_by),
            "cookie_summary": cookie_summary,
            "redirect_chain": sanitized_chain,
            "policy": {
                "missing_header_is_not_safe": True,
                "no_body_or_cookie_values_in_evidence": True,
            },
        },
    )
