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

import contextlib
import hashlib
import http.client
import json
import logging
import re
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

ALLOWED_PORTS = {80, 443}

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
    set_cookie_headers: list[str] | None = None
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

def is_rejected_address(
    address: str,
    network_type: str = "ipv4",
    *,
    allow_loopback: bool = False,
) -> bool:
    """Check if an IP address falls in a rejected category.

    Explicitly blocks cloud metadata endpoints in addition to standard
    private/reserved/loopback ranges. ``allow_loopback`` is a test-only escape
    hatch and must never be enabled in production.
    """
    # Explicit cloud metadata check (regardless of ipaddress classification)
    if address in CLOUD_METADATA_IPS:
        return True

    try:
        addr = ip_address(address)
    except ValueError:
        return True  # malformed, reject

    if allow_loopback and addr.is_loopback:
        return False

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
    *,
    allow_loopback: bool = False,
) -> DNSResolutionEvidence:
    """Validate all DNS resolution answers against security policies.

    Every resolved IP must pass validation. Mixed public/private answers
    result in rejection.
    """
    rejected: list[str] = []
    resolved: list[str] = []

    for ip in resolved_ips:
        if is_rejected_address(
            ip,
            "ipv4" if ":" not in ip else "ipv6",
            allow_loopback=allow_loopback,
        ):
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

def validate_url_scheme(
    url: str,
    *,
    allow_loopback: bool = False,
) -> tuple[bool, str | None]:
    """Validate scheme, host, credentials and port before any DNS or socket I/O.

    ``allow_loopback`` is a test-only escape hatch that also permits a local
    test server to use a non-standard port. Production settings refuse it.
    """
    if not url or not isinstance(url, str):
        return False, "URL is empty or not a string"

    if not url.lower().startswith(("http://", "https://")):
        return False, "Unsupported scheme. Only http:// and https:// are allowed."

    if len(url) > 2048:
        return False, "URL exceeds maximum length of 2048 characters."

    try:
        parsed = urlparse(url)
        if parsed.username or parsed.password:
            return False, "URL must not contain credentials."
        if not parsed.hostname:
            return False, "URL has no hostname."
        port = parsed.port
    except ValueError:
        return False, "URL contains an invalid port."

    loopback_host = (parsed.hostname or "").lower() in {"localhost", "127.0.0.1", "::1"}
    if (
        port is not None
        and port not in ALLOWED_PORTS
        and not (allow_loopback and loopback_host)
    ):
        return False, f"Port {port} is not allowed. Only ports 80 and 443 are permitted."

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


def _json_safe(value: Any) -> Any:
    """Convert ssl certificate structures into JSON-serializable evidence."""
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, bytes):
        return value.hex()
    return value


def build_tls_information(sock: Any, hostname: str, *, verified: bool = True) -> dict[str, Any]:
    """Capture a bounded, serializable TLS summary from a connected socket."""
    cipher = sock.cipher()
    cipher_info: dict[str, Any] | None = None
    if cipher:
        cipher_info = {
            "name": cipher[0],
            "protocol": cipher[1],
            "bits": cipher[2],
        }

    certificate = None
    try:
        certificate = _json_safe(sock.getpeercert())
    except (ValueError, AttributeError):
        certificate = None

    return {
        "enabled": True,
        "verified": verified,
        "protocol": sock.version(),
        "cipher": cipher_info,
        "alpn": sock.selected_alpn_protocol(),
        "server_hostname": hostname,
        "certificate": certificate,
        "error": None,
    }


def _header_value(headers: dict[str, str], name: str) -> str | None:
    target = name.lower()
    for key, value in headers.items():
        if key.lower() == target:
            return value
    return None


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

    def __init__(self, hostname: str, *, allow_loopback: bool = False):
        self.hostname = hostname
        self.allow_loopback = allow_loopback
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
        evidence = validate_dns_answers(
            self.hostname,
            self._resolved_ips,
            allow_loopback=self.allow_loopback,
        )
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

        if port_int not in ALLOWED_PORTS:
            try:
                loopback_pinned = ip_address(pinned_ip).is_loopback
            except ValueError:
                loopback_pinned = False
            if not (resolver.allow_loopback and loopback_pinned):
                raise urllib.error.URLError(
                    f"Port {port_int} is not allowed; only 80 and 443 are permitted"
                )

        path = components["path"]
        query = components["query"]
        if query:
            path = f"{path}?{query}"

        request_start = time.monotonic()
        sock: socket.socket | None = None
        conn: http.client.HTTPConnection | None = None

        try:
            # Create socket connection to pinned IP (no DNS resolution)
            sock = socket.create_connection((pinned_ip, port_int), timeout=self.timeout)

            tls_information: dict[str, Any] | None = None
            if scheme == "https":
                ssl_ctx = self._create_ssl_context(hostname)
                try:
                    # SNI and certificate verification use the original hostname.
                    wrapped_sock = ssl_ctx.wrap_socket(sock, server_hostname=hostname)
                except ssl.SSLCertVerificationError as exc:
                    message = str(exc)[:512]
                    return {
                        "success": False,
                        "http_status": None,
                        "final_url": url,
                        "redirect_location": None,
                        "content_type": None,
                        "html_title": None,
                        "response_headers": {},
                        "set_cookie_headers": [],
                        "body": b"",
                        "tls_information": {
                            "enabled": True,
                            "verified": False,
                            "protocol": None,
                            "cipher": None,
                            "alpn": None,
                            "server_hostname": hostname,
                            "certificate": None,
                            "error": message,
                        },
                        "error": f"TLS certificate verification failed: {message}",
                        "duration_ms": (time.monotonic() - request_start) * 1000,
                    }
                except ssl.SSLError as exc:
                    message = str(exc)[:512]
                    return {
                        "success": False,
                        "http_status": None,
                        "final_url": url,
                        "redirect_location": None,
                        "content_type": None,
                        "html_title": None,
                        "response_headers": {},
                        "set_cookie_headers": [],
                        "body": b"",
                        "tls_information": {
                            "enabled": True,
                            "verified": False,
                            "protocol": None,
                            "cipher": None,
                            "alpn": None,
                            "server_hostname": hostname,
                            "certificate": None,
                            "error": message,
                        },
                        "error": f"TLS handshake failed: {message}",
                        "duration_ms": (time.monotonic() - request_start) * 1000,
                    }

                sock = wrapped_sock
                tls_information = build_tls_information(wrapped_sock, hostname)
                conn = http.client.HTTPSConnection(
                    hostname, port_int, timeout=self.timeout, context=ssl_ctx
                )
                # Replace the connection's socket with our pinned one.
                conn.sock = wrapped_sock
            else:
                conn = http.client.HTTPConnection(
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
            set_cookie_headers: list[str] = []
            for key, value in response.headers.items():
                if key.lower() == "set-cookie":
                    set_cookie_headers.append(value)
                    continue
                if key in response_headers:
                    response_headers[key] = f"{response_headers[key]}, {value}"
                else:
                    response_headers[key] = value

            content_type = _header_value(response_headers, "Content-Type") or ""
            primary_type = (
                content_type.split(";")[0].strip()
                if ";" in content_type
                else content_type
            )

            html_title: str | None = None
            if primary_type == "text/html" and body:
                try:
                    body_str = body.decode("utf-8", errors="replace")
                    title_match = re.search(r"<title>(.*?)</title>", body_str, re.IGNORECASE)
                    if title_match:
                        html_title = title_match.group(1).strip()[:200]
                except Exception:
                    pass

            elapsed_ms = (time.monotonic() - request_start) * 1000

            result: dict[str, Any] = {
                "success": True,
                "http_status": response.status,
                "final_url": url,
                "redirect_location": None,
                "content_type": primary_type,
                "html_title": html_title,
                "response_headers": response_headers,
                "set_cookie_headers": set_cookie_headers,
                "tls_information": tls_information,
                "body": body,
                "duration_ms": elapsed_ms,
            }

            if response.status in (301, 302, 303, 307, 308):
                result["redirect_location"] = _header_value(response_headers, "Location")

            return result

        except urllib.error.URLError:
            raise
        except Exception as e:
            raise urllib.error.URLError(f"Connection failed: {e}") from None
        finally:
            if conn is not None:
                with contextlib.suppress(Exception):
                    conn.close()
            elif sock is not None:
                with contextlib.suppress(Exception):
                    sock.close()


# ---------------------------------------------------------------------------
# Redirect handling with full validation
# ---------------------------------------------------------------------------

def follow_redirects_with_validation(
    url: str,
    max_redirects: int = MAX_REDIRECT_COUNT,
    timeout: float = TOTAL_DEADLINE,
    connection_timeout: float = CONNECTION_TIMEOUT,
    max_response_size: int = MAX_RESPONSE_SIZE,
    allow_loopback: bool = False,
) -> tuple[dict[str, Any], list[str], str | None]:
    redirect_chain: list[str] = [url]
    current_url = url
    start_time = time.monotonic()

    for _ in range(max_redirects + 1):
        if time.monotonic() - start_time > timeout:
            return {}, redirect_chain, "Total deadline exceeded"

        is_valid, error = validate_url_scheme(current_url, allow_loopback=allow_loopback)
        if not is_valid:
            return {}, redirect_chain, error

        components = extract_url_components(current_url)
        hostname = components["hostname"]

        resolver = PinnedDNSResolver(hostname, allow_loopback=allow_loopback)
        dns_evidence = resolver.resolve_and_validate()

        if not dns_evidence.resolution_successful:
            error = dns_evidence.error or "DNS validation failed"
            if error.startswith("DNS resolution failed"):
                return {}, redirect_chain, error
            return {}, redirect_chain, f"DNS validation blocked: {error}"

        transport = PinnedHTTPTransport(
            timeout=connection_timeout,
            max_response_size=max_response_size,
        )
        try:
            result = transport.fetch(current_url, resolver)
        except urllib.error.URLError as e:
            return {}, redirect_chain, f"Fetch failed: {e}"

        if not result.get("success", True):
            return result, redirect_chain, result.get("error", "Fetch failed")

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

    return _evidence_from_fetch(url, result, redirect_chain)


def _evidence_from_fetch(
    url: str,
    result: dict[str, Any],
    redirect_chain: list[str],
    *,
    error: str | None = None,
) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "requested_url": url,
        "final_url": result.get("final_url", url),
        "http_status": result.get("http_status"),
        "content_type": result.get("content_type"),
        "html_title": result.get("html_title"),
        "response_headers": result.get("response_headers", {}),
        "set_cookie_headers": result.get("set_cookie_headers", []),
        "tls_information": result.get("tls_information"),
        "redirect_chain": redirect_chain,
    }
    if error:
        evidence["error"] = error
    return evidence


# ---------------------------------------------------------------------------
# Main scanner orchestration
# ---------------------------------------------------------------------------

@dataclass
class ScannerConfig:
    allow_loopback: bool = False
    max_redirects: int = MAX_REDIRECT_COUNT
    connection_timeout: float = CONNECTION_TIMEOUT
    read_timeout: float = READ_TIMEOUT
    total_deadline: float = TOTAL_DEADLINE
    max_response_size: int = MAX_RESPONSE_SIZE


def scan_url(
    url: str,
    config: ScannerConfig | None = None,
) -> ScanResult:
    if config is None:
        config = ScannerConfig()

    start_time = time.monotonic()
    scan_id = hashlib.sha256(f"{url}{time.time()}".encode()).hexdigest()[:12]

    is_valid, error = validate_url_scheme(url, allow_loopback=config.allow_loopback)
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
        url,
        max_redirects=config.max_redirects,
        timeout=config.total_deadline,
        connection_timeout=config.connection_timeout,
        max_response_size=config.max_response_size,
        allow_loopback=config.allow_loopback,
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
            evidence=_evidence_from_fetch(url, result, redirect_chain, error=error),
            duration_ms=(time.monotonic() - start_time) * 1000,
        )

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

    evidence_dict = _evidence_from_fetch(url, result, redirect_chain)

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