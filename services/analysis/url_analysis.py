"""Deterministic URL analysis engine for PHISHGUARD M3.

Implements URL parsing, domain intelligence, suspicious characteristic detection,
and redirect-chain analysis. All functions are pure (no I/O) and designed to be
independently testable. Network-dependent operations (DNS resolution) are
separated into the M4 scanner module.

The engine produces structured security findings that are kept deterministic
and separate from ML predictions. It does not invent ML features or change
feature meanings.
"""

from __future__ import annotations

import contextlib
import importlib
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlunparse

# Public Suffix List via tldextract (offline, no network at import time)
import tldextract

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum URL length before we flag it as excessive
MAX_URL_LENGTH = 2048

# Maximum redirect count before we flag as potential loop
MAX_REDIRECT_COUNT = 10

# Maximum number of subdomains before flagging
MAX_SUBDOMAINS = 5

# Suspicious TLDs that are commonly abused (brief list; can be extended)
SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "club",
    "online",
    "site",
    "website",
    "info",
    "global",
    "tech",
    "party",
    "download",
    "stream",
    "wiki",
    "loan",
    "racing",
    "gq",
    "ga",
    "ml",
    "cf",
    "tk",
    "click",
    "men",
    "trade",
    "pro",
    "net",
    "org",
}

# Commonly abused port ranges
SUSPICIOUS_PORTS = {25, 135, 445, 3389, 5900, 6000, 65533, 65534, 65535}

# Schemes that are never valid for HTTP-based phishing analysis
DANGEROUS_SCHEMES = {"javascript", "data", "ftp", "file", "about", "blob"}

# Patterns that suggest URL obfuscation
OBFUSCATION_PATTERNS = [
    re.compile(r"%[0-9a-f]{2}%[0-9a-f]{2}"),  # double percent-encoding
    re.compile(r"\\\\x[0-9a-f]{2}"),  # backslash-x encoding
    re.compile(r"\\[0-3][0-7]{0,2}"),  # octal encoding
]

# Patterns suggesting user-info tricks
USER_INFO_PATTERNS = [
    re.compile(r".*@.*\..*"),  # anything@domain.tld pattern
]

# Patterns suggesting IP address in URL
IP_V4_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
IP_V6_PATTERN = re.compile(
    r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$"
)  # simplified


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class URLFeatures:
    """Features extracted from a URL, compatible with M2 live feature set."""
    url_length: int
    domain_length: int
    is_domain_ip: bool
    tld_length: int
    no_of_subdomain: int
    has_obfuscation: bool
    no_of_obfuscated_char: int
    obfuscation_ratio: float
    no_of_letters_in_url: int
    letter_ratio_in_url: float
    no_of_degits_in_url: int  # dataset spelling
    degit_ratio_in_url: float
    no_of_equals_in_url: int
    no_of_qmark_in_url: int
    no_of_ampersand_in_url: int
    no_of_other_special_chars_in_url: int
    spacial_char_ratio_in_url: float
    is_https: bool
    # Additional M3-specific fields
    scheme: str
    hostname: str
    port: int | None
    has_user_info: bool
    path: str
    query: str
    fragment: str
    normalized_hostname: str
    has_suspicious_chars: bool
    suspicious_tld: bool
    subdomain_count: int
    is_ipv4: bool
    is_ipv6: bool
    tld: str
    registered_domain: str


@dataclass(frozen=True)
class SuspiciousFinding:
    """A single suspicious characteristic finding."""
    rule_id: str
    severity: str  # "info" | "low" | "medium" | "high" | "critical"
    evidence: str
    explanation: str
    url_component: str


@dataclass(frozen=True)
class URLAnalysisResult:
    """Complete analysis result for a URL."""
    url_features: URLFeatures
    findings: list[SuspiciousFinding]
    normalized_url: str
    # M2 compatibility: these feature names match the `live` feature manifest
    # so they can be extracted and fed into the M2 model if desired
    extracted_features_for_ml: dict[str, any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# URL parsing and normalization
# ---------------------------------------------------------------------------

def parse_url(raw_url: str) -> tuple[str | None, dict[str, str] | None]:
    """Parse a URL string, returning (normalized_url, error).

    Returns (None, error_dict) if the URL is malformed.
    """
    if not isinstance(raw_url, str):
        return None, {"code": "invalid_url", "message": "URL must be a string"}

    raw_url = raw_url.strip()

    if not raw_url:
        return None, {"code": "invalid_url", "message": "URL is empty"}

    # Scheme validation
    # Must start with http:// or https:// (case-insensitive)
    if not re.match(r"^[hH][tT][tT][pP][sS]?://", raw_url):
        return None, {
            "code": "invalid_url",
            "message": f"Unsupported or missing scheme in URL: {raw_url[:80]}",
        }

    try:
        parsed = importlib.import_module("urllib.parse").urlparse(raw_url)
    except Exception as exc:  # noqa: BLE001 - defensive
        return None, {"code": "invalid_url", "message": f"Failed to parse URL: {exc}"}

    # Validate hostname
    hostname = parsed.hostname
    if not hostname:
        return None, {
            "code": "invalid_url",
            "message": "URL has no hostname",
        }

    # Build normalized URL (lowercase scheme+host, remove default ports)
    scheme = parsed.scheme.lower()
    port = parsed.port

    # Remove default ports
    if scheme == "http" and port == 80:
        port = None
    if scheme == "https" and port == 443:
        port = None

    # Reconstruct hostname: lowercase, handle IDN
    normalized_hostname = hostname.lower()

    # Rebuild netloc
    netloc_parts = [normalized_hostname]
    if port is not None:
        netloc_parts.append(str(port))
    netloc = ":".join(netloc_parts)

    normalized_url = urlunparse((
        scheme,
        netloc,
        parsed.path or "/",
        parsed.params,
        parsed.query,
        "",  # fragment dropped in normalized form
    ))

    return normalized_url, None


def extract_features(parsed_url: Any, raw_url: str) -> URLFeatures:
    """Extract URL features compatible with M2 live feature manifest.

    This is the core extraction that M2 expects. The field names and types
    directly correspond to the `URL_ONLY_FEATURES` defined in
    `services/ml/training/config.py`.

    Args:
        parsed_url: result from urllib.parse.urlparse
        raw_url: the original raw URL string

    Returns:
        URLFeatures dataclass with all fields needed by M2 and M3.
    """

    scheme = parsed_url.scheme.lower()
    hostname = parsed_url.hostname or ""
    normalized_hostname = hostname.lower()
    port = parsed_url.port
    path = parsed_url.path or ""
    query = parsed_url.query or ""
    fragment = parsed_url.fragment or ""

    # --- Basic derivable from URL string ---
    url_length = len(raw_url)
    domain_length = len(hostname)

    # --- IP-based detection ---
    is_domain_ip = bool(
        IP_V4_PATTERN.match(hostname)
        or IP_V6_PATTERN.match(hostname)  # simplified
    )

    # --- TLD & subdomain extraction via tldextract (offline) ---
    extracted = tldextract.extract(hostname)
    tld = extracted.suffix or ""
    tld_length = len(tld)
    subdomain_part = extracted.subdomain or ""
    no_of_subdomain = len(subdomain_part.split(".")) if subdomain_part else 0

    # --- Obfuscation signals ---
    # Count obfuscated characters (non-alphanumeric, non-delimiter)
    # Simple heuristic: characters that are not alnum, hyphen, dot, slash, colon
    special_chars = re.findall(r"[^a-zA-Z0-9./:\-?=]", raw_url)
    no_of_obfuscated_char = len(special_chars)

    # Obfuscation ratio: obfuscated chars / total URL length
    obfuscation_ratio = round(no_of_obfuscated_char / url_length, 4) if url_length else 0.0

    # Letter/digit counts in URL (excluding scheme:// and delimiters)
    stripped = re.sub(r"[^a-zA-Z0-9]", "", raw_url)
    no_of_letters_in_url = sum(1 for c in stripped if c.isalpha())
    letter_ratio_in_url = round(no_of_letters_in_url / url_length, 4) if url_length else 0.0

    no_of_degits_in_url = sum(1 for c in stripped if c.isdigit())
    degit_ratio_in_url = round(no_of_degits_in_url / url_length, 4) if url_length else 0.0

    no_of_equals_in_url = raw_url.count("=")
    no_of_qmark_in_url = raw_url.count("?")
    no_of_ampersand_in_url = raw_url.count("&")

    # "Other" special chars: total special minus equals, ?, &
    all_special = len(re.findall(r"[^a-zA-Z0-9]", raw_url))
    no_of_other_special_chars_in_url = (
        all_special - no_of_equals_in_url - no_of_qmark_in_url - no_of_ampersand_in_url
    )
    spacial_char_ratio_in_url = (
        round(no_of_other_special_chars_in_url / url_length, 4) if url_length else 0.0
    )

    # --- HTTPS scheme ---
    is_https = scheme == "https"

    # --- User info detection ---
    has_user_info = bool(parsed_url.username or parsed_url.password)

    # --- TLD suspicion check ---
    # tldextract gives us the registered domain+suffix; check the suffix alone
    suspicious_tld = tld.lower() in SUSPICIOUS_TLDS

    # --- IP version detection ---
    is_ipv4 = bool(IP_V4_PATTERN.match(hostname))
    is_ipv6 = bool(IP_V6_PATTERN.match(hostname))

    # --- Registered domain (domain + tld) ---
    registered_domain = (
        f"{extracted.domain}.{extracted.suffix}"
        if extracted.domain and extracted.suffix
        else hostname
    )

    return URLFeatures(
        url_length=url_length,
        domain_length=domain_length,
        is_domain_ip=is_domain_ip,
        tld_length=tld_length,
        no_of_subdomain=no_of_subdomain,
        has_obfuscation=obfuscation_ratio > 0.1,  # threshold: >10% special chars
        no_of_obfuscated_char=no_of_obfuscated_char,
        obfuscation_ratio=obfuscation_ratio,
        no_of_letters_in_url=no_of_letters_in_url,
        letter_ratio_in_url=letter_ratio_in_url,
        no_of_degits_in_url=no_of_degits_in_url,
        degit_ratio_in_url=degit_ratio_in_url,
        no_of_equals_in_url=no_of_equals_in_url,
        no_of_qmark_in_url=no_of_qmark_in_url,
        no_of_ampersand_in_url=no_of_ampersand_in_url,
        no_of_other_special_chars_in_url=no_of_other_special_chars_in_url,
        spacial_char_ratio_in_url=spacial_char_ratio_in_url,
        is_https=is_https,
        # M3-specific fields (not in M2 manifest but used for findings)
        scheme=scheme,
        hostname=hostname,
        port=port,
        has_user_info=has_user_info,
        path=path,
        query=query,
        fragment=fragment,
        normalized_hostname=normalized_hostname,
        has_suspicious_chars=False,  # populated during finding phase
        suspicious_tld=suspicious_tld,
        subdomain_count=no_of_subdomain,
        is_ipv4=is_ipv4,
        is_ipv6=is_ipv6,
        tld=tld,
        registered_domain=registered_domain,
    )


# ---------------------------------------------------------------------------
# Suspicious characteristic detection
# ---------------------------------------------------------------------------

def detect_suspicious_features(
    features: URLFeatures,
    raw_url: str,
) -> list[SuspiciousFinding]:
    """Detect suspicious URL characteristics and return findings.

    All detections are deterministic and based solely on the URL string and
    extracted features. No network I/O.
    """
    findings: list[SuspiciousFinding] = []

    # 1. Excessive URL length
    if features.url_length > MAX_URL_LENGTH:
        findings.append(
            SuspiciousFinding(
                rule_id="url_length_excessive",
                severity="high",
                evidence=f"URL length={features.url_length}, max={MAX_URL_LENGTH}",
                explanation="Unusually long URLs can hide the true destination "
                "and are often used in phishing.",
                url_component="full_url",
            )
        )

    # 2. Suspicious character patterns
    # Check for double percent-encoding
    if re.search(r"%[0-9a-f]{2}%[0-9a-f]{2}", raw_url):
        findings.append(
            SuspiciousFinding(
                rule_id="double_percent_encoding",
                severity="medium",
                evidence="Double percent-encoding detected in URL",
                explanation="Double percent-encoding is often used to bypass "
                "filters and hide malicious content.",
                url_component="query+path",
            )
        )

    # 3. Excessive subdomains
    if features.subdomain_count > MAX_SUBDOMAINS:
        findings.append(
            SuspiciousFinding(
                rule_id="excessive_subdomains",
                severity="medium",
                evidence=f"Subdomain count={features.subdomain_count}, max={MAX_SUBDOMAINS}",
                explanation="Many subdomains can indicate a complex, potentially "
                "malicious infrastructure designed to evade detection.",
                url_component="hostname",
            )
        )

    # 4. URL obfuscation (high ratio of special characters)
    if features.has_obfuscation:
        findings.append(
            SuspiciousFinding(
                rule_id="url_obfuscation",
                severity="medium",
                evidence=f"Obfuscation ratio={features.obfuscation_ratio:.2f}",
                explanation="High ratio of special/obfuscated characters in the URL "
                "may indicate attempt to evade detection.",
                url_component="full_url",
            )
        )

    # 5. Misleading authority: user-info (e.g. trusted@attacker.example)
    if features.has_user_info:
        findings.append(
            SuspiciousFinding(
                rule_id="user_info_trick",
                severity="high",
                evidence="URL contains user-info (username/password)",
                explanation="URLs with user-info component can trick users into "
                "thinking the domain is trusted when it is not. Format: "
                "\"user@host\".",
                url_component="authority",
            )
        )

    # 6. Suspicious ports
    if features.port is not None and features.port in SUSPICIOUS_PORTS:
        findings.append(
            SuspiciousFinding(
                rule_id="suspicious_port",
                severity="high",
                evidence=f"Port={features.port} is in suspicious list",
                explanation=f"Port {features.port} is commonly associated with "
                "malware, C2 communication, or vulnerable services.",
                url_component="port",
            )
        )

    # 7. IP address in URL (not a domain name)
    if features.is_domain_ip:
        findings.append(
            SuspiciousFinding(
                rule_id="ip_in_url",
                severity="high",
                evidence="Domain is an IP address",
                explanation="Using an IP address instead of a domain name can "
                "indicate the attacker wants to hide the true site identity "
                "or avoid DNS-based blocklists.",
                url_component="hostname",
            )
        )

    # 8. Suspicious TLD
    if features.suspicious_tld:
        findings.append(
            SuspiciousFinding(
                rule_id="suspicious_tld",
                severity="medium",
                evidence=f"TLD={features.tld} is in commonly-abused list",
                explanation=f"TLD '{features.tld}' is among TLDs frequently "
                "abused by phishing campaigns. This is not conclusive but "
                "indicates elevated risk.",
                url_component="tld",
            )
        )

    # 9. Unicode/IDN homograph indicators
    # If the hostname contains non-ASCII characters
    try:
        features.hostname.encode("idna")
        # If encoding succeeds and the result is different, there are IDN chars
        ascii_hostname = features.hostname.encode("idna").decode("ascii")
        if ascii_hostname != features.hostname.lower():
            findings.append(
                SuspiciousFinding(
                    rule_id="idn_hostname",
                    severity="low",
                    evidence="Internationalized Domain Name detected",
                    explanation="IDN hostnames can be used for homograph attacks "
                    "where visually similar characters from different scripts "
                    "are used to mimic legitimate domains.",
                    url_component="hostname",
                )
            )
    except Exception:
        pass  # not an IDN hostname, skip

    # 10. Scheme mismatch
    if features.scheme not in ("http", "https"):
        # This should have been caught during parsing, but just in case
        findings.append(
            SuspiciousFinding(
                rule_id="unexpected_scheme",
                severity="high",
                evidence=f"Unexpected scheme: {features.scheme}",
                explanation="Non-http(s) schemes may indicate a different "
                "type of resource or an attempt to evade http-based filters.",
                url_component="scheme",
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Redirect-chain analysis
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RedirectHop:
    """One hop in a redirect chain."""
    hop_index: int
    original_url: str
    normalized_url: str
    http_status: int
    final_hostname: str
    evidence: str = ""


def analyze_redirect_chain(
    redirect_urls: list[str],
    max_redirects: int = MAX_REDIRECT_COUNT,
) -> dict[str, Any]:
    """Analyze a redirect chain and return structured findings.

    Args:
        redirect_urls: List of URLs in order of redirection, longest first
            or in chronological order. The first is the originally-requested
            URL, subsequent are redirect destinations.
        max_redirects: Maximum allowed redirect hops.

    Returns:
        Dict with chain analysis results.
    """
    if not redirect_urls:
        return {
            "hops": [],
            "final_url": None,
            "redirect_count": 0,
            "has_loop": False,
            "loop_hop": None,
            "evidence": "No redirect URLs provided",
        }

    hops: list[RedirectHop] = []
    seen_normalized: set[str] = set()
    loop_hop: int | None = None

    for idx, url in enumerate(redirect_urls):
        if idx >= max_redirects:
            # Truncated beyond limit
            truncated = redirect_urls[idx:]
            hops[-1] if hops else None
            return {
                "hops": hops,
                "final_url": url if hops else redirect_urls[0],
                "redirect_count": len(hops),
                "has_loop": False,
                "loop_hop": None,
                "evidence": f"Redirect chain truncated at {max_redirects} hops; "
                f"additional URLs: {len(truncated)}",
            }

        # Normalize each URL
        normalized, parse_error = parse_url(url)
        if parse_error:
            # If we can't parse, record what we have and stop
            hops[-1] if hops else None
            return {
                "hops": hops,
                "final_url": url,
                "redirect_count": len(hops),
                "has_loop": False,
                "loop_hop": None,
                "evidence": f"Failed to parse redirect URL: {parse_error}",
            }

        # Check for loop (same normalized URL seen before)
        norm_key = normalized.lower() if normalized else ""
        if norm_key in seen_normalized and idx > 0:
            loop_index = idx
            # Find which hop caused the loop
            loop_hop = loop_index
            # Don't add this hop; record the loop
            # Actually, let's record it and break
            # Find the first occurrence
            first_occurrence = None
            for i, prev_hop in enumerate(hops):
                if prev_hop.normalized_url.lower() == norm_key:
                    first_occurrence = i
                    break
            if first_occurrence is not None:
                loop_hop = first_occurrence
            # Record finding about the loop
            # We'll add a finding later; just record the loop info
            break

        seen_normalized.add(norm_key)

        # Extract port
        if ":" in normalized.split("/")[2] if normalized else False:
            with contextlib.suppress(ValueError, IndexError):
                int(normalized.split(":")[-1].split("/")[0])

        hop = RedirectHop(
            hop_index=idx,
            original_url=url,
            normalized_url=normalized,
            http_status=200,  # we don't have real HTTP status from passive analysis
            final_hostname=(
                importlib.import_module("urllib.parse").urlparse(normalized).hostname or ""
            ),
            evidence=f"Hop {idx}: {url[:80]}",
        )
        hops.append(hop)

    # Determine final result
    redirect_count = len(hops)
    final_url = hops[-1].normalized_url if hops else None

    result: dict[str, Any] = {
        "hops": hops,
        "final_url": final_url,
        "redirect_count": redirect_count,
        "has_loop": loop_hop is not None,
        "loop_hop": loop_hop,
        "evidence": f"Analyzed {redirect_count} redirect hops",
    }

    if loop_hop is not None:
        result["evidence"] = (
            f"Redirect loop detected at hop {loop_hop}; chain aborted"
        )

    return result


# ---------------------------------------------------------------------------
# ML feature extraction compatibility
# ---------------------------------------------------------------------------

def features_for_ml(features: URLFeatures) -> dict[str, any]:
    """Convert URLFeatures to a dict compatible with M2 live model input.

    The M2 live model expects 18 URL-only features. This function returns
    exactly those fields mapped to their values. This allows the M3 URL
    engine's findings to be combined with/or compared against M2 predictions.

    Returns dict with these keys (matching URL_ONLY_FEATURES order):
    URLLength, DomainLength, IsDomainIP, TLDLength, NoOfSubDomain,
    HasObfuscation, NoOfObfuscatedChar, ObfuscationRatio,
    NoOfLettersInURL, LetterRatioInURL, NoOfDegitsInURL, DegitRatioInURL,
    NoOfEqualsInURL, NoOfQMarkInURL, NoOfAmpersandInURL,
    NoOfOtherSpecialCharsInURL, SpacialCharRatioInURL, IsHTTPS
    """
    return {
        "URLLength": features.url_length,
        "DomainLength": features.domain_length,
        "IsDomainIP": features.is_domain_ip,
        "TLDLength": features.tld_length,
        "NoOfSubDomain": features.no_of_subdomain,
        "HasObfuscation": features.has_obfuscation,
        "NoOfObfuscatedChar": features.no_of_obfuscated_char,
        "ObfuscationRatio": features.obfuscation_ratio,
        "NoOfLettersInURL": features.no_of_letters_in_url,
        "LetterRatioInURL": features.letter_ratio_in_url,
        "NoOfDegitsInURL": features.no_of_degits_in_url,
        "DegitRatioInURL": features.degit_ratio_in_url,
        "NoOfEqualsInURL": features.no_of_equals_in_url,
        "NoOfQMarkInURL": features.no_of_qmark_in_url,
        "NoOfAmpersandInURL": features.no_of_ampersand_in_url,
        "NoOfOtherSpecialCharsInURL": features.no_of_other_special_chars_in_url,
        "SpacialCharRatioInURL": features.spacial_char_ratio_in_url,
        "IsHTTPS": features.is_https,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_url(
    raw_url: str,
) -> URLAnalysisResult:
    """High-level analysis of a single URL.

    Parses the URL, extracts M2-compatible features, detects suspicious
    characteristics, and returns a complete analysis result.

    This is the main entry point for M3 URL analysis. It is pure (no I/O)
    and fully deterministic.

    Args:
        raw_url: The URL string to analyze. Must start with http:// or https://.

    Returns:
        URLAnalysisResult with extracted features and security findings.

    Raises:
        ValueError: If the URL is malformed or has an unsupported scheme.
    """
    # Parse URL
    normalized, parse_error = parse_url(raw_url)
    if parse_error:
        raise ValueError(parse_error["message"])

    # Extract features compatible with M2
    parsed = importlib.import_module("urllib.parse").urlparse(raw_url)
    features = extract_features(parsed, raw_url)

    # Detect suspicious features
    findings = detect_suspicious_features(features, raw_url)

    # Mark features that had findings
    # (We create a new instance since dataclass is frozen)
    updated_findings = list(findings)
    for _finding in updated_findings:
        # Feature is already set during detection; no need to update features
        pass

    # Build ML-compatible extracted features dict
    ml_features = features_for_ml(features)

    # Normalize the URL
    normalized_url = normalized or raw_url

    return URLAnalysisResult(
        url_features=features,
        findings=updated_findings,
        normalized_url=normalized_url,
        extracted_features_for_ml=ml_features,
    )


# Allow running as: python -m phishguard_analysis.url_analysis
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python -m phishguard_analysis.url_analysis <URL>")
        sys.exit(1)
    try:
        result = analyze_url(sys.argv[1])
        print(f"URL: {result.normalized_url}")
        print(f"Features for ML: {result.extracted_features_for_ml}")
        print(f"Findings ({len(result.findings)}):")
        for f in result.findings:
            print(f"  - [{f.severity}] {f.rule_id}: {f.explanation}")
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)