# Chrome extension (M10)

Status: **Implemented and tested locally**. Not published to the Chrome Web
Store and not verified against a production deployment.

The extension is a Manifest V3 on-demand assessment aid. Clicking the toolbar
icon opens a popup that sends the active tab's normalized URL to the PHISHGUARD
backend and renders the returned risk assessment. It does not inspect page
content, block navigation, or monitor browsing in the background.

## Layout and build

| Path | Purpose |
|---|---|
| `apps/extension/src/manifest.template.json` | MV3 manifest with a build-time `__API_ORIGIN__` placeholder |
| `apps/extension/build.ts` | validates the origin, injects the manifest, runs `tsc`, copies popup assets, asserts output |
| `apps/extension/src/service-worker.ts` | message handling, cache/single-flight, bounded backend request |
| `apps/extension/src/popup.*` | popup markup, styles, active-tab read, state rendering |
| `apps/extension/src/lib/` | URL sanitization, response validation, backend client, cache, gate, view model |
| `apps/extension/tests/` | URL, parser, backend, cache, gate, message, contract parity, privacy and build tests |

There is no bundler. The build uses the repository's TypeScript 5.9 compiler to
emit native ES modules, then writes `dist/manifest.json`.

```bash
# development build against the local web app
pnpm --filter @phishguard/extension build

# production-style build against a deployed origin (must be HTTPS)
PHISHGUARD_API_ORIGIN=https://phishguard.example.com \
  pnpm --filter @phishguard/extension build

# verification
pnpm --filter @phishguard/extension test
pnpm --filter @phishguard/extension typecheck
cd apps/extension && node build.ts
```

Load `apps/extension/dist` through `chrome://extensions` → **Load unpacked**.

The origin is fixed at build time. The extension has no runtime endpoint setting,
so a compromised message cannot redirect browsing data to another host. Remote
plaintext HTTP origins are rejected; `http://localhost:3000` and
`http://127.0.0.1:*` are accepted for local development only.

## Backend endpoint

`POST {PHISHGUARD_API_ORIGIN}/api/scan`

The extension calls the public web endpoint, not `/internal/analyze` (which
requires the server-only `X-Service-Token`). Requests are anonymous:

```json
{
  "url": "https://example.com/login?page=2",
  "options": { "include_intel": true, "include_ct": false, "timeout_ms": 12000 }
}
```

A successful call returns `200` with the contract `ScanResult`. Anonymous scans
are not persisted by `services/analysis`; only a verified Supabase session sets a
persistence owner. The extension never sends cookies, an `Authorization` header,
or an API key. See `docs/api-contracts.md` for the wire contract.

## Permissions and rationale

| Permission | Why it is needed | What it does not grant |
|---|---|---|
| `activeTab` | Read the URL of the tab whose toolbar action the user just clicked, and grant that one tab temporarily | No persistent access to arbitrary tabs, no page content injection |
| `host_permissions: ["{origin}/*"]` | Send the normalized URL to the single configured PHISHGUARD backend origin | No `<all_urls>`, no wildcard origin, no third-party hosts |

Not requested: `tabs`, `scripting`, `storage`, `cookies`, `history`,
`webRequest`, `webNavigation`, `downloads`, `clipboardRead`, `geolocation`.
There are no content scripts, no optional permissions, no externally connectable
pages, and no web-accessible resources.

The extension uses a module service worker and a popup only. It has no options
page, no content script, no injected overlay, no badge polling, and no tab event
listeners.

## Privacy protections

- Only `http` and `https` pages are eligible. `localhost`, `.localhost`,
  `.local`, `.internal`, `.home.arpa`, single-label hosts, and
  loopback/private/reserved/link-local IPv4 and IPv6 literals are rejected before
  any network call.
- Non-default ports are rejected.
- Embedded URL credentials are removed and reported to the user.
- The fragment is removed.
- Query parameters commonly carrying secrets or identifiers (`token`,
  `access_token`, `session`, `PHPSESSID`, `password`, `otp`, `jwt`, `signature`,
  `assertion`, `ticket`, `email`, `state`, `code`, `nonce`, and similar) are
  removed before the request and the count is shown in the popup.
- URLs longer than 2048 characters after normalization are not assessed.
- No page text, form values, passwords, keystrokes, cookies, clipboard contents,
  or browsing history are read or transmitted.
- The popup renders backend strings with `textContent`; there is no HTML
  injection, dynamic code evaluation, or remote script.
- The backend response is treated as untrusted: 512 KiB read cap, no redirects,
  `credentials: "omit"`, `referrerPolicy: "no-referrer"`, and strict field
  validation before rendering.
- Cached entries are keyed by a SHA-256 hash of the normalized URL. The URL
  itself is never stored. The cache lives in service-worker memory only, expires
  after 5 minutes, holds at most 32 entries, and is discarded when the worker is
  suspended or the browser closes. The popup has a **Clear cached result** button.

## Request behavior and states

One request is sent per popup open or **Recheck** click. There is no polling,
retry loop, badge, or background monitoring. Duplicate concurrent requests for
the same normalized URL share a single in-flight request. A sequence gate drops
stale responses if the active tab or URL changes before a response arrives.

| Backend result | Popup state |
|---|---|
| `high` / `critical` band | **High-risk evidence**, score and observed reasons |
| `suspicious` band | **Suspicious characteristics** |
| `guarded` band | **Some caution indicators** |
| `low` band | **Low observed risk** — wording explicitly avoids "safe" |
| `insufficient_evidence` / `score: null` | **Incomplete assessment**, no score, missing evidence listed |
| Missing coverage (`incomplete`, `partial`) | Coverage label states that missing evidence is not safe |
| `queued` / `running` | Unavailable: assessment did not finish |
| Timeout, offline, 429, 5xx, rejected target, malformed body | Unavailable; never rendered as safe |

Timeouts: the extension aborts at 20 s and asks the backend for a 12 s scan. The
service worker has no retry logic. A `429` is surfaced as rate limiting and does
not become a verdict. Server-side rate limiting is not implemented yet (M9 audit
item D4), so the extension deliberately avoids request amplification.

## Limitations

- Scores are provisional, uncalibrated heuristics, not probabilities. A low band
  is an observation about available evidence, not a safety guarantee.
- Evidence coverage is normally below 100% (brand evidence is unavailable in
  M7), so most live results are shown as incomplete.
- The extension never blocks a page and does not replace a browser's built-in
  safe-browsing protection.
- It does not assess intra-page behavior, downloads, forms, or credentials typed
  after load.
- It requires the PHISHGUARD backend to be reachable. Offline and backend
  failures are reported as unavailable.
- Cross-origin access relies on the single `host_permissions` entry. The web
  endpoint's CORS configuration is unchanged.
- Packaging was validated with `google-chrome-stable --pack-extension`; store
  review, signing-key management, and production deployment remain out of scope.

## Verification performed

- `pnpm --filter @phishguard/extension test`: 65 tests passing across URL
  sanitization, response parsing (complete/partial/high/low/suspicious/guarded/
  malformed), backend status mapping, timeouts, oversized bodies, cache TTL and
  epochs, single-flight, request gating, messages, contract parity, static
  privacy/manifest checks, and the production build.
- `pnpm --filter @phishguard/extension typecheck` and root `pnpm lint` pass.
- `node build.ts` emits the package; Chrome packed it successfully with
  `google-chrome-stable --pack-extension`.
