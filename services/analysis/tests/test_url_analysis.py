"""M3 URL analysis tests using controlled fixtures only.

No real network access. All tests use synthetic URLs and mocked data.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add the services/analysis directory to sys.path so that url_analysis
# and scanner modules are importable directly
_svc_analysis = Path(__file__).resolve().parent.parent
if str(_svc_analysis) not in sys.path:
    sys.path.insert(0, str(_svc_analysis))

from url_analysis import (  # noqa: E402
    analyze_url,
    extract_features,
    features_for_ml,
    parse_url,
)


def test_parse_url_valid_https() -> None:
    normalized, error = parse_url("https://www.example.com/path?query=1#frag")
    assert error is None
    assert normalized == "https://www.example.com/path?query=1"


def test_parse_url_valid_http() -> None:
    normalized, error = parse_url("http://example.com/")
    assert error is None
    assert normalized == "http://example.com/"


def test_parse_url_missing_scheme() -> None:
    normalized, error = parse_url("example.com/")
    assert error is not None


def test_parse_url_empty() -> None:
    normalized, error = parse_url("")
    assert error is not None


def test_extract_features_basic() -> None:
    import urllib.parse
    parsed = urllib.parse.urlparse("http://example.com/path?q=1")
    features = extract_features(parsed, "http://example.com/path?q=1")
    assert features.url_length > 0
    assert features.domain_length > 0
    assert features.is_domain_ip is False
    assert features.tld_length > 0
    assert features.no_of_subdomain == 0
    assert features.has_obfuscation is False
    assert features.obfuscation_ratio == 0.0
    assert features.is_https is False


def test_extract_features_ipv4() -> None:
    import urllib.parse
    parsed = urllib.parse.urlparse("http://192.168.1.1/page")
    features = extract_features(parsed, "http://192.168.1.1/page")
    assert features.is_domain_ip is True


def test_extract_features_https() -> None:
    import urllib.parse
    parsed = urllib.parse.urlparse("https://example.com/")
    features = extract_features(parsed, "https://example.com/")
    assert features.is_https is True


def test_features_for_ml_has_all_18_keys() -> None:
    import urllib.parse
    parsed = urllib.parse.urlparse("http://example.com/path")
    features = extract_features(parsed, "http://example.com/path")
    ml_features = features_for_ml(features)
    expected_keys = {
        "URLLength", "DomainLength", "IsDomainIP", "TLDLength", "NoOfSubDomain",
        "HasObfuscation", "NoOfObfuscatedChar", "ObfuscationRatio",
        "NoOfLettersInURL", "LetterRatioInURL", "NoOfDegitsInURL", "DegitRatioInURL",
        "NoOfEqualsInURL", "NoOfQMarkInURL", "NoOfAmpersandInURL",
        "NoOfOtherSpecialCharsInURL", "SpacialCharRatioInURL", "IsHTTPS",
    }
    assert set(ml_features.keys()) == expected_keys
    assert len(ml_features) == 18


def test_analyze_url_basic() -> None:
    result = analyze_url("http://example.com/path?q=1#frag")
    assert result.normalized_url == "http://example.com/path?q=1"
    assert len(result.findings) >= 0
    assert result.extracted_features_for_ml is not None
    assert set(result.extracted_features_for_ml.keys()) == {
        "URLLength", "DomainLength", "IsDomainIP", "TLDLength", "NoOfSubDomain",
        "HasObfuscation", "NoOfObfuscatedChar", "ObfuscationRatio",
        "NoOfLettersInURL", "LetterRatioInURL", "NoOfDegitsInURL", "DegitRatioInURL",
        "NoOfEqualsInURL", "NoOfQMarkInURL", "NoOfAmpersandInURL",
        "NoOfOtherSpecialCharsInURL", "SpacialCharRatioInURL", "IsHTTPS",
    }


def test_analyze_url_localhost() -> None:
    result = analyze_url("http://localhost:3000/")
    assert result.normalized_url is not None


def test_analyze_url_ipv4() -> None:
    result = analyze_url("http://192.168.1.1/page")
    ip_findings = [f.rule_id for f in result.findings if "ip" in f.rule_id]
    assert len(ip_findings) > 0


def test_analyze_url_suspicious_tld() -> None:
    result = analyze_url("http://example.xyz/page")
    tld_findings = [f.rule_id for f in result.findings if f.rule_id == "suspicious_tld"]
    assert len(tld_findings) > 0