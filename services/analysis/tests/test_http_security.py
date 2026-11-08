"""Deterministic M6 HTTP security-header tests. No network access."""

from __future__ import annotations

from http_security import assess_http_security, sanitize_url_for_evidence

GOOD_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=()",
}


def test_good_https_headers_produce_no_findings() -> None:
    result = assess_http_security(
        "https://example.com/login",
        GOOD_HEADERS,
        http_status=200,
        set_cookie_headers=["session=abc; Secure; HttpOnly; SameSite=Lax"],
        redirect_chain=["https://example.com/login"],
    )

    assert result.status == "ok"
    assert result.findings == ()
    assert result.evidence["https"] is True
    assert result.evidence["missing_headers"] == []
    assert result.evidence["cookie_summary"]["missing_secure"] == 0


def test_missing_headers_are_reported() -> None:
    result = assess_http_security("https://example.com/", {"Server": "nginx/1.2.3"})

    ids = {finding["id"] for finding in result.findings}
    assert "hsts_missing" in ids
    assert "csp_missing" in ids
    assert "x_content_type_options_missing" in ids
    assert "x_frame_options_missing" in ids
    assert "server_version_disclosure" in ids


def test_http_url_is_high_severity() -> None:
    result = assess_http_security("http://example.com/", GOOD_HEADERS)

    finding = next(f for f in result.findings if f["id"] == "http_not_https")
    assert finding["severity"] == "high"
    assert result.evidence["https"] is False


def test_missing_response_headers_is_unknown_not_safe() -> None:
    result = assess_http_security(
        "https://example.com/",
        None,
        scan_error="connection reset",
    )

    assert result.status == "unknown"
    assert result.error == "connection reset"
    assert result.evidence["reason"] == "no_response_headers"


def test_cookie_values_are_not_in_evidence() -> None:
    result = assess_http_security(
        "https://example.com/",
        GOOD_HEADERS,
        set_cookie_headers=["session=super-secret-value; SameSite=None"],
    )

    ids = {finding["id"] for finding in result.findings}
    assert "cookie_missing_secure" in ids
    assert "cookie_missing_httponly" in ids
    assert "cookie_samesite_none_without_secure" in ids
    assert "super-secret-value" not in repr(result.evidence)


def test_insecure_redirect_is_reported() -> None:
    result = assess_http_security(
        "https://example.com/",
        GOOD_HEADERS,
        redirect_chain=["http://example.com/", "https://example.com/"],
    )

    assert any(f["id"] == "http_insecure_redirect" for f in result.findings)


def test_evidence_url_drops_query_and_fragment() -> None:
    sanitized = sanitize_url_for_evidence(
        "https://user:pass@example.com/path?token=secret#fragment"
    )
    assert sanitized == "https://example.com/path"
    assert "secret" not in sanitized
