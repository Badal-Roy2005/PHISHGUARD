# Threat intelligence (M5B)

Status: **M5B implemented and tested; consumed by M7.** Google Safe Browsing
and URLhaus are integrated into the analysis request path as the `intel` engine.
M7 preserves each provider state as evidence; a no-match or provider failure is
never converted into a safe verdict.

## Providers

| Provider | Adapter | Endpoint | Credential |
|---|---|---|---|
| Google Safe Browsing | `SafeBrowsingProvider` | `POST https://safebrowsing.googleapis.com/v4/threatMatches:find` | `GOOGLE_SAFE_BROWSING_API_KEY` |
| URLhaus | `URLhausProvider` | `POST https://urlhaus-api.abuse.ch/v1/url/` | `URLHAUS_API_KEY` (`Auth-Key` header) |

Provider-specific parsing is isolated in `services/analysis/threat_intel.py`.
The common interface is `BaseProvider.lookup(url) -> ProviderResult`.

## Normalized states

Every provider result is one of:

| Status | Meaning | Safe? |
|---|---|---|
| `match` | Provider reported the URL as malicious. | No; evidence of risk. |
| `no_match` | Provider did not report a match. | **No.** It is only absence of evidence from this provider. |
| `unavailable` | Missing key, timeout, outage, auth failure, rate limit/quota. | **No.** |
| `error` | Malformed/unexpected response, invalid input, oversized response. | **No.** |

The aggregated `intel` engine status is `ok` only when every provider returned a
usable `match`/`no_match`; it is `partial` when at least one provider is usable
and another is not; `unknown` when no provider is usable but at least one was
attempted; `error` when all attempted providers failed; and `skipped` when no
provider is configured or the request disabled intel.

A provider failure never suppresses another provider's valid result. The
aggregate evidence always contains `provider_statuses`, `match_providers`,
`no_match_providers`, `unavailable_providers`, `error_providers` and
`cache_hits`.

## Environment variables

| Variable | Default | Notes |
|---|---|---|
| `GOOGLE_SAFE_BROWSING_API_KEY` | empty | Server-only. Empty -> provider `unavailable` / engine `skipped`. |
| `URLHAUS_API_KEY` | empty | Server-only. Empty -> provider `unavailable` / engine `skipped`. |
| `INTEL_HTTP_TIMEOUT_SECONDS` | `5` | Per-attempt connect/read/write/pool timeout, 0.5-15. |
| `INTEL_MAX_RESPONSE_BYTES` | `256000` | Streaming response cap, 1024-2000000. |
| `INTEL_MAX_RETRIES` | `1` | Retries only connect/timeout errors and HTTP 500/502/503/504. |
| `INTEL_CACHE_ENABLED` | `true` | In-process TTL cache for `match`/`no_match` only. |
| `INTEL_SAFE_BROWSING_CACHE_TTL_SECONDS` | `3600` | Safe Browsing freshness window. |
| `INTEL_URLHAUS_CACHE_TTL_SECONDS` | `21600` | URLhaus freshness window. |

Never put these values in `NEXT_PUBLIC_*`, browser code, the Chrome extension,
logs, fixtures or screenshots. `/internal/config` reports only
`configured`/`skipped` and non-secret bounds.

## Setup

### Google Safe Browsing

1. Enable the **Safe Browsing API** in a Google Cloud project.
2. Create an API key and restrict it to the Safe Browsing API and the server
   egress (where your host supports key restrictions).
3. Set `GOOGLE_SAFE_BROWSING_API_KEY` on `services/analysis` only.
4. Review the quota in the Google Cloud console. This project does not assume a
   specific quota; HTTP 429 or quota errors become `unavailable` and are not
   retried.

### URLhaus

1. Create/obtain a URLhaus API key from abuse.ch.
2. Set `URLHAUS_API_KEY` on `services/analysis` only. The adapter sends it in the
   `Auth-Key` header, never in a URL.
3. Review abuse.ch's published API rate limits. HTTP 429 and URLhaus
   `rate_limited` statuses become `unavailable` and are not retried.

## Request/response flow

1. `/internal/analyze` validates the contract (`ScanRequest`).
2. The existing M3 URL engine runs (no network).
3. The M6 transport engines consume one scanner result for TLS and HTTP evidence.
4. The intel engine builds provider adapters from validated server settings.
5. Each adapter:
   - rejects non-http(s), over-length or credential-bearing URLs before egress;
   - consults the in-process TTL cache for `match`/`no_match`;
   - sends a bounded, fixed-endpoint POST with no redirect following;
   - streams at most `INTEL_MAX_RESPONSE_BYTES`;
   - retries only safe idempotent failures within the retry/deadline budget;
   - normalizes the result and records provider metadata, reference, lookup time
     and expiry.
6. The aggregator keeps every provider's state distinct and emits contract
   `Finding` objects only for `match` results.
7. M7 consumes the provider states as risk factors. `match` contributes to
   threat likelihood; `no_match`, `unavailable` and `error` remain visible and
   affect coverage, not safety.

Example intel evidence (abridged):

```json
{
  "providers": {
    "google_safe_browsing": {
      "status": "match", "reason": null, "cached": false,
      "looked_up_at": "2026-11-08T12:00:00Z",
      "expires_at": "2026-11-08T13:00:00Z",
      "findings": [{
        "provider": "google_safe_browsing", "status": "match",
        "provider_reference": null, "category": "social_engineering",
        "severity": "high",
        "metadata": { "threat_type": "SOCIAL_ENGINEERING" }
      }]
    },
    "urlhaus": {
      "status": "unavailable", "reason": "upstream_unavailable",
      "error": "URLhaus is unavailable (HTTP 503)",
      "findings": [{
        "provider": "urlhaus", "status": "unavailable",
        "queried_url": "https://example.com/login",
        "category": null, "error": "URLhaus is unavailable (HTTP 503)"
      }]
    }
  },
  "provider_statuses": {
    "google_safe_browsing": "match", "urlhaus": "unavailable"
  },
  "policy": {
    "no_match_is_not_safe": true,
    "provider_failure_is_not_safe": true,
    "missing_credentials_is_not_safe": true
  }
}
```

## Local development

- Leave both keys empty. Providers are not called; the intel engine reports
  `skipped` and each provider reports `unavailable` with
  `reason = missing_credentials`. This is the default for tests.
- Unit tests use `httpx.MockTransport`; no test contacts a provider or a live
  malicious URL.
- To exercise a real provider locally, set a key in a gitignored `.env` and run
  the analysis service. Do not use known-malicious URLs for demos; use a
  controlled fixture URL and expect `no_match`.

## Limitations

- The cache is in-process and per-instance; it is not the Supabase `intel_cache`
  table (M8). A restart or a different replica starts cold.
- Safe Browsing does not expose a per-match record identifier, so
  `provider_reference` is `null`; URLhaus references are preserved.
- URLhaus `query_status` values are mapped defensively; unknown values become
  `error`, never `no_match`.
- No live malicious URLs were queried while implementing or testing this
  milestone.
