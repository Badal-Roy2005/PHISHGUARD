"""Isolated website scanner for PHISHGUARD M4.

Implements outbound website scanning with strict security boundaries:
- Protocol and destination restrictions
- DNS validation and rebinding protection
- DNS-to-connection binding (IP pinning)
- Explicit redirect handling (no automatic redirects)
- Resource restrictions (timeouts, size limits)
- Safe website inspection without script execution
- Structured evidence and error reporting

The scanner never executes downloaded code, does not use a headless browser,
and fails closed whenever destination safety cannot be established.
"""

from __future__ import annotations

import hashlib
import json
import logging
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Security policies and constants
# ---------------------------------------------------------------------------

ALLOWED_PROTOCOLS = {"http", "https"}

DISALLOWED_PORTS = {25, 135, 445, 3389, 5900, 6000, 65533, 65534, 65535}

MAX_REDIRECT_COUNT = 10

CONNECTION_TIMEOUT = 10
READ_TIMEOUT = 10
TOTAL_DEADLINE = 30

MAX_RESPONSE_SIZE = 1_000_000

ALLOWED_CONTENT_TYPES = {
    "text/html",
    "application/json",
    "application/xml",
    "text/plain",
}

TLS_VERIFY = True

# Cloud metadata endpoints - explicitly blocked regardless of Python's ipaddress classification
CLOUD_METADATA_IPS = {
    "169.254.169.254",  # AWS/GCP/Azure metadata
    "169.254.170.2",    # AWS ECS metadata
    "fd00:ec2::254",     # AWS IPv6 metadata
    "100.100.100.200",  # Alibaba Cloud metadata
    "100.100.100.254",  # Tencent Cloud metadata
}

# Cloud metadata hostname patterns
CLOUD_METADATA_HOSTNAMES = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata",
    "metadata.aws.internal",
    "169.254.170.2",
}


# ---------------------------------------------------------------------------
# Evidence data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DNSResolutionEvidence:
    hostname: str
    requested_addresses: list[str]
    resolved_addresses: list[str]
    rejected_addresses: list[str]
    resolution_successful: bool
    error: str | None = None


@dataclass(frozen=True)
class ScanEvidence:
    scan_id: str
    requested_url: str
    final_url: str | None
    redirect_chain: list[str] = field(default_factory=list)
    dns_evidence: DNSResolutionEvidence | None = None
    http_status: int | None = None
    tls_information: dict[str, Any] | None = None
    response_headers: dict[str, str] | None = None
    html_title: str | None = None
    content_type: str | None = None
    scan_duration_ms: float = 0.0
    error: str | None = None
    blocked_reason: str | None = None


@dataclass(frozen=True)
class ScanResult:
    scan_id: str
    url: str
    status: str
    risk_band: str | None
    findings: list[dict[str, Any]] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0


# ---------------------------------------------------------------------------
# DNS validation and rebinding protection
# ---------------------------------------------------------------------------

def is_rejected_address(address: str, network_type: str = "ipv4") -> bool:
    """Check if an IP address falls in a rejected category.

    Explicitly blocks cloud metadata endpoints in addition to standard
    private/reserved/loopback ranges.
    """
    # Explicit cloud metadata check (regardless of ipaddress classification)
    if address in CLOUD_METADATA_IPS:
        return True

    try:
        addr = ip_address(address)
    except ValueError:
        return True  # malformed, reject

    if network_type == "ipv4":
        if addr.is_loopback:
            return True
        if addr.is_link_local:
            return True
        if addr.is_unspecified:
            return True
        if addr.is_private:
            return True
        if addr.is_reserved:
            return True
        if address.startswith("169.254."):
            return True
    elif network_type == "ipv6":
        if addr.is_loopback:
            return True
        if addr.is_link_local:
            return True
        if addr.is_private:
            return True
        if addr.is_unspecified:
            return True
        if not addr.is_global:
            return True
        if address.startswith("fe80:"):
            return True

    return False


def validate_dns_answers(
    hostname: str,
    resolved_ips: list[str],
) -> DNSResolutionEvidence:
    """Validate all DNS resolution answers against security policies.

    Every resolved IP must pass validation. Mixed public/private answers
    result in rejection.
    """
    rejected: list[str] = []
    resolved: list[str] = []

    for ip in resolved_ips:
        if is_rejected_address(ip, "ipv4" if ":" not in ip else "ipv6"):
            rejected.append(ip)
        else:
            resolved.append(ip)

    success = len(rejected) == 0 and len(resolved) > 0

    return DNSResolutionEvidence(
        hostname=hostname,
        requested_addresses=[],
        resolved_addresses=resolved,
        rejected_addresses=rejected,
        resolution_successful=success,
        error=(
            f"All DNS answers rejected as prohibited addresses: {rejected}"
            if not success
            else None
        ),
    )


# ---------------------------------------------------------------------------
# URL validation and parsing (no network)
# ---------------------------------------------------------------------------

def validate_url_scheme(url: str) -> tuple[bool, str | None]:
    if not url or not isinstance(url, str):
        return False, "URL is empty or not a string"

    if not url.lower().startswith(("http://", "https://")):
        return False, "Unsupported scheme. Only http:// and https:// are allowed."

    if len(url) > 2048:
        return False, "URL exceeds maximum length of 2048 characters."

    return True, None


def extract_url_components(url: str) -> dict[str, str]:

    parsed = urlparse(url)
    return {
        "scheme": parsed.scheme,
        "hostname": parsed.hostname or "",
        "port": str(parsed.port) if parsed.port else "",
        "path": parsed.path or "/",
        "query": parsed.query,
        "fragment": parsed.fragment,
    }


# ---------------------------------------------------------------------------
# DNS-to-connection binding (IP pinning)
# ---------------------------------------------------------------------------

class PinnedDNSResolver:
    """Resolves a hostname and pins the connection to a validated IP.

    This prevents DNS rebinding attacks by:
    1. Resolving the hostname once
    2. Validating all returned addresses
    3. Storing the validated addresses for connection
    4. Preventing re-resolution during connection
    """

    def __init__(self, hostname: str):
        self.hostname = hostname
        self._resolved_ips: list[str] = []
        self._validated_ips: list[str] = []
        self._validation_complete = False

    def resolve_and_validate(self) -> DNSResolutionEvidence:
        try:
            addr_info = socket.getaddrinfo(self.hostname, None, family=socket.AF_UNSPEC)
        except socket.gaierror as e:
            return DNSResolutionEvidence(
                hostname=self.hostname,
                requested_addresses=[],
                resolved_addresses=[],
                rejected_addresses=[],
                resolution_successful=False,
                error=f"DNS resolution failed: {e}",
            )

        self._resolved_ips = [ip[4][0] for ip in addr_info]
        evidence = validate_dns_answers(self.hostname, self._resolved_ips)
        self._validated_ips = evidence.resolved_addresses
        self._validation_complete = evidence.resolution_successful

        return evidence

    @property
    def validated_ips(self) -> list[str]:
        return self._validated_ips

    @property
    def is_validated(self) -> bool:
        return self._validation_complete

    def get_connection_address(self) -> str | None:
        if not self._validation_complete or not self._validated_ips:
            return None
        return self._validated_ips[0]


# ---------------------------------------------------------------------------
# Pinned HTTP transport (no automatic redirects, IP-pinned connection, SNI)
# ---------------------------------------------------------------------------

class PinnedHTTPTransport:
    """HTTP transport that pins connections to validated IPs.

    Features:
    - No automatic redirect following
    - DNS resolution happens once, with validation
    - Connection is pinned to a validated IP
    - Host header preserves original hostname
    - TLS SNI and certificate verification use original hostname
    - No proxy bypass (proxy env vars are ignored)
    """

    def __init__(
        self,
        timeout: int = CONNECTION_TIMEOUT,
        max_response_size: int = MAX_RESPONSE_SIZE,
    ):
        self.timeout = timeout
        self.max_response_size = max_response_size
        self.logger = logging.getLogger("phishguard.scanner.transport")

    def _create_ssl_context(self, hostname: str) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    def fetch(
        self,
        url: str,
        resolver: PinnedDNSResolver,
    ) -> dict[str, Any]:
        if not resolver.is_validated:
            raise urllib.error.URLError("DNS validation not completed successfully")

        components = extract_url_components(url)
        hostname = components["hostname"]
        scheme = components["scheme"]
        port_str = components["port"]

        if port_str:
            port_int = int(port_str)
        elif scheme == "https":
            port_int = 443
        else:
            port_int = 80

        pinned_ip = resolver.get_connection_address()
        if not pinned_ip:
            raise urllib.error.URLError("No validated IP address available")

        path = components["path"]
        query = components["query"]
        if query:
            path = f"{path}?{query}"

        # Create socket connection to pinned IP (no DNS resolution)
        sock = socket.create_connection(
            (pinned_ip, port_int), timeout=self.timeout
        )

        try:
            if scheme == "https":
                ssl_ctx = self._create_ssl_context(hostname)
                # Wrap socket with TLS using original hostname for SNI
                # and certificate verification
                wrapped_sock = ssl_ctx.wrap_socket(
                    sock, server_hostname=hostname
                )
                conn = __import__("http.client").HTTPSConnection(
                    hostname, port_int, timeout=self.timeout, context=ssl_ctx
                )
                # Replace the connection's socket with our pinned one
                conn.sock = wrapped_sock
            else:
                conn = __import__("http.client").HTTPConnection(
                    hostname, port_int, timeout=self.timeout
                )
                conn.sock = sock

            headers = {
                "Host": hostname,
                "User-Agent": "PHISHGUARD-Scanner/1.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "identity",
                "Connection": "close",
            }

            conn.request("GET", path, headers=headers)
            response = conn.getresponse()

            body = response.read(self.max_response_size + 1)
            if len(body) > self.max_response_size:
                body = body[: self.max_response_size]

            response_headers: dict[str, str] = {}
            for key, value in response.headers.items():
                response_headers[key] = value

            content_type = response_headers.get("Content-Type", "")
            primary_type = (
                content_type.split(";")[0].strip()
                if ";" in content_type
                else content_type
            )

            html_title: str | None = None
            if primary_type == "text/html" and body:
                try:
                    body_str = body.decode("utf-8", errors="replace")
                    title_match = __import__("re").search(
                        r"<title>(.*?)</title>",
                        body_str,
                        __import__("re").IGNORECASE,
                    )
                    if title_match:
                        html_title = title_match.group(1).strip()[:200]
                except Exception:
                    pass

            elapsed_ms = (time.monotonic() - (time.monotonic() - self.timeout)) * 1000

            result: dict[str, Any] = {
                "success": True,
                "http_status": response.status,
                "final_url": url,
                "redirect_location": None,
                "content_type": primary_type,
                "html_title": html_title,
                "response_headers": response_headers,
                "body": body,
                "duration_ms": elapsed_ms,
            }

            if response.status in (301, 302, 303, 307, 308):
                result["redirect_location"] = response_headers.get("Location")

            conn.close()
            return result

        except Exception as e:
            conn.close()
            raise urllib.error.URLError(f"Connection failed: {e}") from None


# ---------------------------------------------------------------------------
# Redirect handling with full validation
# ---------------------------------------------------------------------------

def follow_redirects_with_validation(
    url: str,
    max_redirects: int = MAX_REDIRECT_COUNT,
    timeout: int = TOTAL_DEADLINE,
) -> tuple[dict[str, Any], list[str], str | None]:
    redirect_chain: list[str] = [url]
    current_url = url
    start_time = time.monotonic()

    for _ in range(max_redirects + 1):
        if time.monotonic() - start_time > timeout:
            return {}, redirect_chain, "Total deadline exceeded"

        is_valid, error = validate_url_scheme(current_url)
        if not is_valid:
            return {}, redirect_chain, error

        components = extract_url_components(current_url)
        hostname = components["hostname"]

        try:
            socket.getaddrinfo(hostname, None, family=socket.AF_UNSPEC)
        except socket.gaierror as e:
            return {}, redirect_chain, f"DNS resolution failed: {e}"

        resolver = PinnedDNSResolver(hostname)
        dns_evidence = resolver.resolve_and_validate()

        if not dns_evidence.resolution_successful:
            return {}, redirect_chain, f"DNS validation blocked: {dns_evidence.error}"

        transport = PinnedHTTPTransport(timeout=CONNECTION_TIMEOUT)
        try:
            result = transport.fetch(current_url, resolver)
        except urllib.error.URLError as e:
            return {}, redirect_chain, f"Fetch failed: {e}"

        if result.get("redirect_location"):
            redirect_url = result["redirect_location"]

            if not redirect_url.startswith(("http://", "https://")):
                from urllib.parse import urljoin
                redirect_url = urljoin(current_url, redirect_url)

            if redirect_url in redirect_chain:
                return {}, redirect_chain, f"Redirect loop detected: {redirect_url}"

            redirect_chain.append(redirect_url)
            current_url = redirect_url
        else:
            return result, redirect_chain, None

    return {}, redirect_chain, f"Too many redirects ({len(redirect_chain)} hops)"


# ---------------------------------------------------------------------------
# Redirect-chain analysis (passive, no follow)
# ---------------------------------------------------------------------------

def analyze_redirects_passive(
    redirect_urls: list[str],
    max_hops: int = MAX_REDIRECT_COUNT,
) -> dict[str, Any]:
    if not redirect_urls:
        return {
            "hop_count": 0,
            "has_loop": False,
            "final_url": None,
            "evidence": "No URLs provided",
        }

    normalized: list[str] = []
    seen: set[str] = set()
    loop_hop: int | None = None

    for idx, url in enumerate(redirect_urls):
        if idx >= max_hops:
            break

        try:
            from urllib.parse import urlparse
            p = urlparse(url)
            host = (p.hostname or "").lower()
            port_info = ""
            if p.port and (
                p.scheme == "http" and p.port != 80
                or p.scheme == "https" and p.port != 443
            ):
                port_info = f":{p.port}"

            normalized_url = f"{p.scheme}://{host}{port_info}{p.path or '/'}"
        except Exception:
            normalized_url = url.lower()

        norm_lower = normalized_url.lower()
        if norm_lower in seen and idx > 0:
            loop_hop = idx
            break

        seen.add(norm_lower)
        normalized.append(normalized_url)

    has_loop = loop_hop is not None

    return {
        "hop_count": len(normalized),
        "has_loop": has_loop,
        "final_url": normalized[-1] if normalized else None,
        "hop_details": normalized,
        "evidence": f"Analyzed {len(normalized)} redirect hops; loop={has_loop}",
    }


# ---------------------------------------------------------------------------
# Website inspection (safe, read-only)
# ---------------------------------------------------------------------------

def inspect_website_safe(
    url: str,
    http_client: Any = None,
) -> dict[str, Any]:
    result, redirect_chain, error = follow_redirects_with_validation(url)

    if error:
        raise urllib.error.URLError(error)

    evidence: dict[str, Any] = {
        "requested_url": url,
        "final_url": result.get("final_url", url),
        "http_status": result.get("http_status"),
        "content_type": result.get("content_type"),
        "html_title": result.get("html_title"),
        "response_headers": result.get("response_headers", {}),
        "redirect_chain": redirect_chain,
    }

    return evidence


# ---------------------------------------------------------------------------
# Main scanner orchestration
# ---------------------------------------------------------------------------

@dataclass
class ScannerConfig:
    allow_loopback: bool = False
    max_redirects: int = MAX_REDIRECT_COUNT
    connection_timeout: int = CONNECTION_TIMEOUT
    read_timeout: int = READ_TIMEOUT
    total_deadline: int = TOTAL_DEADLINE
    max_response_size: int = MAX_RESPONSE_SIZE


def scan_url(
    url: str,
    config: ScannerConfig | None = None,
) -> ScanResult:
    if config is None:
        config = ScannerConfig()

    start_time = time.monotonic()
    scan_id = hashlib.sha256(f"{url}{time.time()}".encode()).hexdigest()[:12]

    is_valid, error = validate_url_scheme(url)
    if not is_valid:
        return ScanResult(
            scan_id=scan_id,
            url=url,
            status="failed",
            risk_band="critical",
            findings=[{"rule_id": "invalid_scheme", "severity": "critical", "detail": error}],
            evidence={"error": error},
            duration_ms=(time.monotonic() - start_time) * 1000,
        )

    result, redirect_chain, error = follow_redirects_with_validation(
        url, max_redirects=config.max_redirects, timeout=config.total_deadline
    )

    if error:
        findings: list[dict[str, Any]] = []

        if "DNS validation blocked" in error:
            findings.append({
                "rule_id": "blocked_address",
                "severity": "critical",
                "detail": error,
            })
        elif "DNS resolution failed" in error:
            findings.append({
                "rule_id": "dns_failure",
                "severity": "critical",
                "detail": error,
            })
        else:
            findings.append({
                "rule_id": "fetch_blocked",
                "severity": "critical",
                "detail": error,
            })

        return ScanResult(
            scan_id=scan_id,
            url=url,
            status="failed",
            risk_band="critical",
            findings=findings,
            evidence={"error": error, "redirect_chain": redirect_chain},
            duration_ms=(time.monotonic() - start_time) * 1000,
        )

    try:
        evidence = inspect_website_safe(url)
    except urllib.error.URLError as e:
        evidence = {
            "requested_url": url,
            "final_url": url,
            "error": f"Inspection blocked: {e}",
        }

    findings = []

    if len(redirect_chain) > config.max_redirects:
        findings.append({
            "rule_id": "excessive_redirects",
            "severity": "high",
            "detail": f"Redirect chain has {len(redirect_chain)} hops, exceeding limit",
        })

    content_type = result.get("content_type", "")
    if content_type and content_type not in ALLOWED_CONTENT_TYPES:
        findings.append({
            "rule_id": "unsupported_content_type",
            "severity": "medium",
            "detail": f"Content type '{content_type}' not in allowed list",
        })

    for hop in redirect_chain:
        if any(meta_ip in hop for meta_ip in CLOUD_METADATA_IPS):
            findings.append({
                "rule_id": "cloud_metadata_access",
                "severity": "critical",
                "detail": f"Redirect chain contains cloud metadata endpoint: {hop}",
            })

    status = "complete"
    if findings:
        status = "partial"

    critical_findings = [f for f in findings if f.get("severity") == "critical"]
    high_findings = [f for f in findings if f.get("severity") == "high"]

    if critical_findings:
        risk_band = "critical"
    elif high_findings:
        risk_band = "high"
    elif findings:
        risk_band = "suspicious"
    else:
        risk_band = "low"

    evidence_dict: dict[str, Any] = {
        "requested_url": url,
        "final_url": result.get("final_url", url),
        "http_status": result.get("http_status"),
        "content_type": result.get("content_type"),
        "html_title": evidence.get("html_title"),
        "response_headers": evidence.get("response_headers", {}),
        "tls_information": evidence.get("tls_information"),
        "redirect_chain": redirect_chain,
    }

    if evidence.get("html_title"):
        evidence_dict["html_title"] = evidence["html_title"]

    duration_ms = (time.monotonic() - start_time) * 1000

    return ScanResult(
        scan_id=scan_id,
        url=url,
        status=status,
        risk_band=risk_band,
        findings=findings,
        evidence=evidence_dict,
        duration_ms=duration_ms,
    )


if __name__ == "__main__":
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else "http://example.com/"
    result = scan_url(url)
    print(json.dumps(asdict(result), indent=2, default=str))
    sys.exit(0)