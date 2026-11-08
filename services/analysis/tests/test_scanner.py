"""M4 scanner tests using controlled fixtures only.

No real network access. All tests use synthetic scenarios and mocked DNS.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add the services/analysis parent directory to sys.path so that the
# analysis module (url_analysis, scanner) is importable directly
_svc_analysis = Path(__file__).resolve().parent.parent
if str(_svc_analysis) not in sys.path:
    sys.path.insert(0, str(_svc_analysis))

from scanner import (  # noqa: E402
    DNSResolutionEvidence,
    PinnedDNSResolver,
    PinnedHTTPTransport,
    ScanResult,
    analyze_redirects_passive,
    build_tls_information,
    extract_url_components,
    follow_redirects_with_validation,
    is_rejected_address,
    scan_url,
    validate_dns_answers,
    validate_url_scheme,
)


def test_validate_url_scheme_valid() -> None:
    is_valid, error = validate_url_scheme("https://example.com/")
    assert is_valid is True
    assert error is None


def test_validate_url_scheme_invalid() -> None:
    is_valid, error = validate_url_scheme("ftp://example.com/")
    assert is_valid is False
    assert error is not None


def test_validate_url_scheme_empty() -> None:
    is_valid, error = validate_url_scheme("")
    assert is_valid is False


def test_validate_url_scheme_too_long() -> None:
    long_url = "http://" + "a" * 2100 + ".com/"
    is_valid, error = validate_url_scheme(long_url)
    assert is_valid is False


def test_extract_url_components_basic() -> None:
    components = extract_url_components("https://www.example.com:443/path?q=1")
    assert components["scheme"] == "https"
    assert components["hostname"] == "www.example.com"
    assert components["port"] == "443"
    assert components["path"] == "/path"
    assert components["query"] == "q=1"


def test_extract_url_components_no_port() -> None:
    components = extract_url_components("http://example.com/path")
    assert components["port"] == ""


def test_is_rejected_loopback_ipv4() -> None:
    assert is_rejected_address("127.0.0.1", "ipv4") is True


def test_is_rejected_link_local_ipv4() -> None:
    assert is_rejected_address("169.254.0.1", "ipv4") is True


def test_is_rejected_unspecified_ipv4() -> None:
    assert is_rejected_address("0.0.0.0", "ipv4") is True


def test_is_rejected_private_ipv4() -> None:
    assert is_rejected_address("10.0.0.1", "ipv4") is True
    assert is_rejected_address("172.16.0.1", "ipv4") is True
    assert is_rejected_address("192.168.1.1", "ipv4") is True


def test_is_rejected_loopback_ipv6() -> None:
    assert is_rejected_address("::1", "ipv6") is True


def test_is_rejected_link_local_ipv6() -> None:
    assert is_rejected_address("fe80::1", "ipv6") is True


def test_is_rejected_unique_local_ipv6() -> None:
    assert is_rejected_address("fc00::1", "ipv6") is True


def test_validate_dns_answers_all_ok() -> None:
    evidence = validate_dns_answers("example.com", ["93.184.216.34"])
    assert evidence.resolution_successful is True
    assert evidence.rejected_addresses == []


def test_validate_dns_answers_all_rejected() -> None:
    evidence = validate_dns_answers("example.com", ["127.0.0.1"])
    assert evidence.resolution_successful is False
    assert len(evidence.rejected_addresses) > 0


def test_validate_dns_answers_mixed() -> None:
    evidence = validate_dns_answers("example.com", ["93.184.216.34", "127.0.0.1"])
    assert evidence.resolution_successful is False
    assert "127.0.0.1" in evidence.rejected_addresses


def test_scan_url_invalid_scheme() -> None:
    result = scan_url("ftp://example.com/")
    assert result.status == "failed"
    assert result.risk_band == "critical"
    assert any(f["rule_id"] == "invalid_scheme" for f in result.findings)


def test_scan_url_private_ip() -> None:
    result = scan_url("http://10.0.0.1/somepage")
    assert result.status in ("failed", "partial")


def test_scan_url_redirect_loop() -> None:
    redirect_urls = [
        "http://example.com/",
        "http://example.org/",
        "http://example.com/",
    ]
    result = analyze_redirects_passive(redirect_urls)
    assert result["has_loop"] is True


def test_scan_url_redirect_within_limit() -> None:
    redirect_urls = [
        "http://example.com/",
        "http://example.org/page1",
        "http://example.org/page2",
    ]
    result = analyze_redirects_passive(redirect_urls)
    assert result["has_loop"] is False
    assert result["hop_count"] == 3


def test_analyze_redirects_empty() -> None:
    result = analyze_redirects_passive([])
    assert result["hop_count"] == 0
    assert result["has_loop"] is False


def test_scan_result_has_required_fields() -> None:
    result = ScanResult(
        scan_id="test123",
        url="http://example.com/",
        status="complete",
        risk_band="low",
        findings=[],
        evidence={},
        duration_ms=100.0,
    )
    assert result.scan_id == "test123"
    assert result.url == "http://example.com/"
    assert result.status == "complete"
    assert result.risk_band == "low"
    assert result.findings == []
    assert result.evidence == {}
    assert result.duration_ms == 100.0


def test_scan_result_minimal() -> None:
    result = ScanResult(
        scan_id="m4",
        url="http://test.com/",
        status="failed",
        risk_band="critical",
        findings=[{"rule_id": "blocked", "severity": "critical", "detail": "test"}],
        evidence={"error": "blocked"},
        duration_ms=50.0,
    )
    assert result.risk_band == "critical"
    assert len(result.findings) == 1
    assert result.findings[0]["rule_id"] == "blocked"


def test_dns_evidence_creation() -> None:
    evidence = DNSResolutionEvidence(
        hostname="example.com",
        requested_addresses=["93.184.216.34"],
        resolved_addresses=["93.184.216.34"],
        rejected_addresses=[],
        resolution_successful=True,
    )
    assert evidence.hostname == "example.com"
    assert evidence.resolution_successful is True
    assert evidence.rejected_addresses == []


def test_dns_evidence_all_rejected() -> None:
    evidence = DNSResolutionEvidence(
        hostname="example.com",
        requested_addresses=["127.0.0.1"],
        resolved_addresses=[],
        rejected_addresses=["127.0.0.1"],
        resolution_successful=False,
        error="Loopback address rejected",
    )
    assert evidence.resolution_successful is False
    assert "127.0.0.1" in evidence.rejected_addresses
    assert evidence.error == "Loopback address rejected"


def test_ml_feature_compatibility() -> None:
    from url_analysis import analyze_url, features_for_ml

    result = analyze_url("http://example.com/path?q=1#frag")
    ml_features = features_for_ml(result.url_features)
    assert len(ml_features) == 18
    assert ml_features["IsDomainIP"] is False
    assert ml_features["IsHTTPS"] is False
    assert ml_features["URLLength"] > 0
    assert ml_features["DomainLength"] > 0

def test_validate_url_rejects_credentials_and_disallowed_ports() -> None:
    assert validate_url_scheme("https://user:pass@example.com/")[0] is False
    assert validate_url_scheme("https://example.com:8443/")[0] is False
    assert validate_url_scheme("https://example.com:99999/")[0] is False
    assert validate_url_scheme("https://example.com:443/")[0] is True


def test_build_tls_information_is_json_safe() -> None:
    class FakeSocket:
        def cipher(self):
            return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

        def version(self):
            return "TLSv1.3"

        def selected_alpn_protocol(self):
            return "h2"

        def getpeercert(self):
            return {
                "subject": ((("commonName", "example.com"),),),
                "issuer": ((("commonName", "Example CA"),),),
                "notBefore": "Nov  1 00:00:00 2026 GMT",
                "notAfter": "Nov  1 00:00:00 2027 GMT",
                "subjectAltName": (("DNS", "example.com"),),
            }

    info = build_tls_information(FakeSocket(), "example.com")

    assert info["verified"] is True
    assert info["protocol"] == "TLSv1.3"
    assert info["cipher"]["bits"] == 256
    assert info["certificate"]["subject"][0][0][0] == "commonName"


def test_follow_redirects_propagates_tls_evidence(monkeypatch) -> None:
    def fake_resolve(self):
        return DNSResolutionEvidence(
            hostname=self.hostname,
            requested_addresses=["93.184.216.34"],
            resolved_addresses=["93.184.216.34"],
            rejected_addresses=[],
            resolution_successful=True,
        )

    def fake_fetch(self, url, resolver):
        return {
            "success": True,
            "http_status": 200,
            "final_url": url,
            "redirect_location": None,
            "content_type": "text/html",
            "html_title": "Example",
            "response_headers": {"Strict-Transport-Security": "max-age=31536000"},
            "set_cookie_headers": ["a=1; Secure"],
            "tls_information": {"verified": True, "protocol": "TLSv1.3"},
            "body": b"ok",
            "duration_ms": 1.0,
        }

    monkeypatch.setattr(PinnedDNSResolver, "resolve_and_validate", fake_resolve)
    monkeypatch.setattr(PinnedHTTPTransport, "fetch", fake_fetch)

    result, chain, error = follow_redirects_with_validation("https://example.com/")

    assert error is None
    assert chain == ["https://example.com/"]
    assert result["tls_information"]["protocol"] == "TLSv1.3"
    assert result["set_cookie_headers"] == ["a=1; Secure"]


def test_follow_redirects_preserves_tls_failure_evidence(monkeypatch) -> None:
    def fake_resolve(self):
        return DNSResolutionEvidence(
            hostname=self.hostname,
            requested_addresses=["93.184.216.34"],
            resolved_addresses=["93.184.216.34"],
            rejected_addresses=[],
            resolution_successful=True,
        )

    def fake_fetch(self, url, resolver):
        return {
            "success": False,
            "final_url": url,
            "tls_information": {
                "verified": False,
                "protocol": None,
                "certificate": None,
                "error": "certificate verify failed",
            },
            "error": "TLS certificate verification failed",
        }

    monkeypatch.setattr(PinnedDNSResolver, "resolve_and_validate", fake_resolve)
    monkeypatch.setattr(PinnedHTTPTransport, "fetch", fake_fetch)

    result, chain, error = follow_redirects_with_validation("https://example.com/")

    assert error == "TLS certificate verification failed"
    assert result["tls_information"]["verified"] is False
    assert chain == ["https://example.com/"]


def test_loopback_override_is_explicit_and_test_only() -> None:
    assert is_rejected_address("127.0.0.1", "ipv4") is True
    assert is_rejected_address("127.0.0.1", "ipv4", allow_loopback=True) is False
    evidence = validate_dns_answers(
        "localhost",
        ["127.0.0.1"],
        allow_loopback=True,
    )
    assert evidence.resolution_successful is True


def test_loopback_override_allows_a_test_server_port() -> None:
    assert validate_url_scheme("http://127.0.0.1:8000/")[0] is False
    assert validate_url_scheme("http://127.0.0.1:8000/", allow_loopback=True)[0] is True
    assert validate_url_scheme("https://example.com:8443/", allow_loopback=True)[0] is False
