# Transport security (M6)

Status: **M6 implemented and tested locally; consumed by M7.** TLS, HTTP
security headers and Certificate Transparency are integrated as the `tls` and
`http` engines. M7 turns their findings into deterministic risk factors; missing
or failed checks reduce evidence coverage and are never treated as safe.

## Components

| Path | Responsibility |
|---|---|
| `services/analysis/scanner.py` | only target fetch; DNS pinning, redirect revalidation, port/credential policy, TLS capture |
| `services/analysis/tls_assessment.py` | pure TLS/certificate interpretation |
| `services/analysis/http_security.py` | pure HTTP header/cookie interpretation |
| `services/analysis/certificate_transparency.py` | bounded crt.sh lookup (fixed endpoint) |
| `services/analysis/app/transport.py` | consumes scanner evidence once and builds `tls`/`http` engine reports |

The scanner is called once per scan. TLS and HTTP assessment never fetch the
target again. No response body or cookie value is copied into engine evidence.

## Scanner changes

- Allowed ports are exactly `80` and `443`; URL credentials are rejected before
  DNS or socket I/O.
- HTTPS connections use the original hostname for SNI and certificate
  verification while connecting to the validated pinned IP.
- TLS evidence captures `verified`, protocol, cipher name/bits, ALPN, server
  hostname and certificate subject/issuer/validity/SAN count.
- Certificate verification failures are preserved as evidence and reported as
  `tls_certificate_untrusted` rather than being collapsed into a generic fetch
  error.
- Duplicate `Set-Cookie` headers are preserved separately from the normalized
  response-header map.
- Redirects are still followed manually; every destination is re-resolved and
  revalidated.

## TLS engine

`status = ok` means the TLS assessment is usable; it does **not** mean the site
is safe. Findings include:

- untrusted certificate chain (critical)
- expired or not-yet-valid certificate (critical/high)
- certificate expiring within 14/30 days (high/medium)
- obsolete protocol such as TLS 1.0/1.1 (high)
- cipher strength below 128 bits (high)

`unknown` means no TLS evidence was produced. `skipped` means the final URL is
HTTP. `partial` means some TLS evidence was missing.

## HTTP engine

The HTTP engine evaluates the final response and redirect chain:

- final URL not HTTPS, or an HTTP hop in the redirect chain
- HSTS presence, max-age and `includeSubDomains`
- CSP presence and `'unsafe-inline'` / `'unsafe-eval'`
- `X-Content-Type-Options`, clickjacking protection, `Referrer-Policy`,
  `Permissions-Policy`
- server/framework version disclosure
- cookie `Secure`, `HttpOnly`, `SameSite`, and `SameSite=None` without `Secure`

Missing headers produce findings, never a clean result. `unknown` means no
response headers were captured.

## Certificate Transparency

CT is **off by default** (`CT_ENABLED=false`). It runs only when the request sets
`options.include_ct=true` and the server flag is enabled. The query uses the
fixed `https://crt.sh/` endpoint; the domain is a query parameter, never a
connection host.

| Variable | Default | Notes |
|---|---|---|
| `CT_ENABLED` | `false` | Enables the CT lookup path. |
| `CT_TIMEOUT_SECONDS` | `5` | Per-lookup timeout, 0.5–15. |
| `CT_MAX_RESPONSE_BYTES` | `1000000` | Streaming response cap. |
| `CT_MAX_RECORDS` | `1000` | Maximum records processed. |

A requested CT lookup that is disabled, rate-limited, times out or fails makes
the `tls` engine `partial` and preserves all TLS findings. CT statuses are
`ok | skipped | unavailable | error`; none of them imply safety. There is no
shared CT cache yet.

## Verification

Tests use fake scanners, fake TLS evidence and `httpx.MockTransport` for crt.sh.
No test contacts a live target, crt.sh or a malicious site.
