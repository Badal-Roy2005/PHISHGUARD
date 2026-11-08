# Security model

## Trust boundaries

| Asset | Trust |
|---|---|
| Target URL and anything fetched from it | **untrusted, attacker-controlled** |
| User-submitted report text | untrusted input |
| Supabase service-role key | server-only; full DB access |
| Safe Browsing / URLhaus keys | server-only; billable |
| ML artifacts | trusted, versioned, checksummed |
| Browser (anon key only) | untrusted client |

## Hard invariants

1. Outbound requests happen **only** inside `services/analysis/scanner`.
2. Scheme allowlist: `http`, `https`. Ports: 80, 443 (test-only override).
3. No credentials in URLs, no cookies, no `Authorization` forwarding.
4. Downloaded content is never executed or rendered.
5. `unknown`, `skipped`, `error` never map to a low-risk verdict.
6. Service-role key never reaches a browser bundle or `NEXT_PUBLIC_*`.
7. No live malicious site is ever visited for a test or demo.

## SSRF / DNS-rebinding controls (M4)

Order of operations:

1. Parse and normalize (contracts layer, no DNS).
2. Resolve **all** A/AAAA records via `getaddrinfo`.
3. Reject if **any** resolved address is denied:
   loopback, private, link-local, reserved, CGNAT `100.64/10`, `0.0.0.0/8`,
   `198.18/15`, multicast, unspecified, IPv6 ULA `fc00::/7`, `fe80::/10`,
   `::1`, IPv4-mapped `::ffff:0:0/96`.
4. Connect to the **validated IP**, preserving `Host` and TLS SNI.
5. Redirects are followed manually (max 5); every hop is re-resolved and
   revalidated.
6. Limits: connect 3 s, total 8 s, body 1 MB, `GET`/`HEAD` only.

**Residual risk (documented, not hidden):** a full DNS-rebinding defence requires a
socket-level connect pin. `httpx` does not expose that cleanly. Connecting to the
validated IP narrows the TOCTOU window but does not close it completely. An
`httpcore` custom network backend is the P1 hardening step.

## Abuse and cost controls

| Control | Value (configurable) |
|---|---|
| anonymous scans | 10/min per IP |
| authenticated scans | 30/min per user |
| concurrent scans | 8 |
| URL length | 2048 |
| request body | small, schema-bounded |
| intel cache | Safe Browsing 1 h, URLhaus 6 h |

## Application security

- Request validation runs before any queueing or fetch (`validateScanRequest` /
  Pydantic `ScanRequest`).
- Errors never include secrets, raw target responses or stack traces.
- `/internal/*` requires a constant-time token comparison (`hmac.compare_digest`).
- CORS is an explicit allowlist; `*` is refused in production.
- Production startup fails if tokens are missing or weak, or if the loopback
  test override is set.
- Report text is stored as data and rendered as text (no `dangerouslySetInnerHTML`).
- RLS is the only authorization boundary for client reads; policies are tested with
  the anon key, not just declared.

## Secrets handling

| Secret | Where |
|---|---|
| `SUPABASE_SERVICE_ROLE_KEY` | Python services only |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | browser (safe by design, requires RLS) |
| `GOOGLE_SAFE_BROWSING_API_KEY` | analysis service only |
| `URLHAUS_API_KEY` | analysis service only |
| `INTERNAL_SERVICE_TOKEN`, `ML_SERVICE_TOKEN` | server-to-server headers |

`.env` is gitignored; `.env.example` contains names only. `/internal/config`
returns a redacted summary (`configured` / `skipped`), never values.

## Threat matrix

| Threat | Control | Test |
|---|---|---|
| SSRF to metadata service | deny-set + resolved-IP validation | M4 matrix |
| DNS rebinding | connect-to-IP, per-hop revalidation | M4 (residual documented) |
| Redirect to internal host | manual loop + revalidation | M4 |
| Decompression bomb | 1 MB streaming cap | M4 |
| Slow target | connect/total timeouts | M4 |
| Enumeration / cost abuse | rate limits, concurrency cap | M9/M11 |
| RLS bypass | anon-key cross-user tests | M8 |
| Key leakage | grep check in CI, redacted config | M11 |
| XSS via report text | text rendering only | M9 |
| Label inversion | class-count + label-map assertions | M2 |
