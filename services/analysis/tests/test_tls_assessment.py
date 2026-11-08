"""Deterministic M6 TLS assessment tests. No network access."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from tls_assessment import assess_tls


def _cert_time(delta_days: int) -> str:
    value = datetime.now(UTC) + timedelta(days=delta_days)
    return value.strftime("%b %d %H:%M:%S %Y GMT")


def _tls_info(*, protocol: str = "TLSv1.3", verified: bool = True) -> dict:
    return {
        "enabled": True,
        "verified": verified,
        "protocol": protocol,
        "cipher": {"name": "TLS_AES_256_GCM_SHA384", "protocol": protocol, "bits": 256},
        "alpn": "http/1.1",
        "server_hostname": "example.com",
        "certificate": {
            "subject": [[("commonName", "example.com")]],
            "issuer": [[("commonName", "Example CA")]],
            "notBefore": _cert_time(-1),
            "notAfter": _cert_time(365),
            "subjectAltName": [["DNS", "example.com"]],
        },
        "error": None,
    }


def test_https_tls_is_usable_and_clean() -> None:
    result = assess_tls("https://example.com/login", _tls_info())

    assert result.status == "ok"
    assert result.findings == ()
    assert result.evidence["verified"] is True
    assert result.evidence["protocol"] == "TLSv1.3"
    assert result.evidence["certificate"]["subject"] == "example.com"


def test_http_final_url_is_skipped_not_safe() -> None:
    result = assess_tls("http://example.com/", None)

    assert result.status == "skipped"
    assert result.findings[0]["id"] == "tls_not_used"
    assert result.evidence["reason"] == "not_https"


def test_missing_tls_evidence_is_unknown() -> None:
    result = assess_tls("https://example.com/", None, scan_error="connection reset")

    assert result.status == "unknown"
    assert result.error == "connection reset"
    assert result.evidence["reason"] == "tls_unavailable"


def test_untrusted_certificate_is_critical() -> None:
    info = _tls_info(verified=False)
    info["certificate"] = None
    info["protocol"] = None
    result = assess_tls("https://example.com/", info)

    assert result.status == "partial"
    assert any(f["id"] == "tls_certificate_untrusted" for f in result.findings)
    assert any(f["severity"] == "critical" for f in result.findings)


def test_expired_certificate_is_critical() -> None:
    info = _tls_info()
    info["certificate"]["notBefore"] = _cert_time(-365)
    info["certificate"]["notAfter"] = _cert_time(-1)

    result = assess_tls("https://example.com/", info)

    assert result.status == "ok"
    assert any(f["id"] == "tls_certificate_expired" for f in result.findings)


def test_weak_protocol_is_flagged() -> None:
    result = assess_tls("https://example.com/", _tls_info(protocol="TLSv1.1"))

    assert result.status == "ok"
    finding = next(f for f in result.findings if f["id"] == "tls_weak_protocol")
    assert finding["severity"] == "high"


def test_tls_evidence_drops_query_strings() -> None:
    result = assess_tls(
        "https://example.com/login?token=super-secret",
        _tls_info(),
        redirect_chain=["https://example.com/?token=super-secret"],
    )

    serialized = repr(result.evidence)
    assert "super-secret" not in serialized
    assert "token" not in serialized
