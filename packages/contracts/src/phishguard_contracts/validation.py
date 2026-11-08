"""Structural URL validation and normalization.

No DNS resolution and no network I/O happen here. Address-blocking (SSRF) is
the scanner's responsibility (M4); the API layer only rejects structurally
invalid or non-http(s) input.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

MAX_URL_LENGTH = 2048
MIN_URL_LENGTH = 8
ALLOWED_SCHEMES = frozenset({"http", "https"})
DEFAULT_PORTS = {"http": 80, "https": 443}


class UrlValidationError(ValueError):
    """Raised when a URL fails structural validation."""

    def __init__(self, message: str, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class TargetUrl:
    normalized: str
    scheme: str
    hostname: str
    port: int
    is_ip_literal: bool


def _looks_like_ip(host: str) -> bool:
    """Cheap literal check; the scanner performs authoritative validation."""
    if host.startswith("[") and host.endswith("]"):
        return True
    return all(part.isdigit() for part in host.split(".")) and host.count(".") == 3


def normalize_url(raw: str) -> TargetUrl:
    if not isinstance(raw, str):
        raise UrlValidationError("url must be a string", "not_a_string")

    value = raw.strip()
    if len(value) < MIN_URL_LENGTH:
        raise UrlValidationError(f"url must be at least {MIN_URL_LENGTH} characters", "too_short")
    if len(value) > MAX_URL_LENGTH:
        raise UrlValidationError(f"url must be at most {MAX_URL_LENGTH} characters", "too_long")

    parts = urlsplit(value)
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UrlValidationError("url scheme must be http or https", "bad_scheme")
    if parts.username or parts.password:
        raise UrlValidationError("url must not contain credentials", "credentials")
    if not parts.hostname:
        raise UrlValidationError("url must include a hostname", "no_host")

    host = parts.hostname.lower().rstrip(".")
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".localhost"):
        raise UrlValidationError("url host is not permitted", "localhost")

    try:
        port = parts.port or DEFAULT_PORTS[scheme]
    except ValueError as exc:  # malformed port
        raise UrlValidationError("url port is invalid", "bad_port") from exc

    if not (1 <= port <= 65535):
        raise UrlValidationError("url port is out of range", "bad_port")

    netloc = f"[{host}]" if ":" in host else host
    if port != DEFAULT_PORTS[scheme]:
        netloc = f"{netloc}:{port}"

    # Fragments are never sent over the wire; drop them so scans are reproducible.
    normalized = urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))

    return TargetUrl(
        normalized=normalized,
        scheme=scheme,
        hostname=host,
        port=port,
        is_ip_literal=_looks_like_ip(host),
    )
