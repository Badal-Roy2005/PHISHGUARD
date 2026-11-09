# PHISHGUARD Chrome Extension

On-demand phishing risk assessment for the active tab via the PHISHGUARD backend.

> **Note**: This is an extension aid, not a safety guarantee. It does not block
> navigation, nor does it inspect page content, passwords, or cookies.

## Quick start

```bash
# build the extension
pnpm --filter @phishguard/extension build

# load it in Chrome (no packaging step required):
#   chrome://extensions → enable "Developer mode" → "Load unpacked" → select apps/extension/dist
```

## Build reference

| Command | Purpose |
|---|---|
| `pnpm --filter @phishguard/extension build` | Run `node build.ts` with defaults; output goes to `apps/extension/dist/` |
| `PHISHGUARD_API_ORIGIN=https://example.com pnpm --filter @phishguard/extension build` | Build against a production origin (must be HTTPS; loopback HTTP is rejected) |
| `pnpm --filter @phishguard/extension test` | Run the test suite (65 tests, URL sanitization → contract parity → build) |
| `pnpm --filter @phishguard/extension typecheck` | Run `tsc --noEmit` on the extension source |

The build injects the `PHISHGUARD_API_ORIGIN` into both `host_permissions` and
`connect-src` CSP, then emits TypeScript→ESM via the repo's native `tsc` (no
esbuild/Vite). The extension has no bundler and no runtime config.

## Permissions

The extension only asks for the minimal required capabilities:

- `activeTab` — read the URL of the tab opened by the action-click
- `host_permissions: ["{origin}/*"]` — the single backend origin, injected at build time

No `tabs`, `<all_urls>`, `scripting`, `storage`, `cookies`, `webRequest`,
`webNavigation`, `history`, `downloads`, `clipboardRead`, `geolocation`.

## Architecture

1. User clicks the toolbar icon.
2. The popup queries `chrome.tabs.query({active:true, lastFocusedWindow:true})` and reads the tab URL.
3. The URL is normalized by `sanitizeUrl()` (removing credentials, fragments, and sensitive query params).
4. The normalized URL is sent via `chrome.runtime.sendMessage` to the background service worker.
5. The service worker checks its in-memory cache (keyed by SHA-256 of the normalized URL, TTL 5 min, max 32 entries). A cache hit returns the cached data with `cached: true`; a miss sends a single `POST /api/scan` request to the backend.
6. The backend returns a `ScanResult` which the service worker validates, parses, and stores in the cache.
7. The message flows back to the popup, which renders the assessment state (high-risk, suspicious, guarded, low, incomplete) using `textContent` only.

There are no content scripts, no page monitoring, no polling, no auto-refresh, and no background navigation hook. Each assessment is user-initiated and one-shot.

## Privacy and data handling

- Only `http` and `https` pages are eligible; all local/private/reserved hosts are rejected before any network I/O.
- Embedded URL credentials are removed and reported.
- Sensitive query parameters (token, session, password, otp, jwt, etc.) are removed; the count is shown in the popup.
- The fragment is removed.
- The backend response is treated as untrusted: 512 KiB read cap, strict field validation, `textContent` rendering only.
- Cache entries are keyed by SHA-256 of the normalized URL. The URL itself is never stored. The cache expires after 5 minutes, holds at most 32 entries, and is cleared on SW suspension or via the popup's "Clear cached result" button.
- No page text, form contents, passwords, keystrokes, cookies, clipboard, browsing history, or HTML injection is collected, stored, or transmitted.

## Caching and rate limits

- One request per popup open or Recheck click. No polling, no retries, no background monitoring.
- In-flight deduplication via a single-flight map prevents duplicate requests for the same normalized URL.
- Cache epoch prevents stale responses after a clear.
- The backend's rate limits are not yet implemented (M9 audit item D4), so the extension deliberately avoids request amplification.

## State-to-UI mapping

| Backend band | Popup headline | State label |
|---|---|---|
| `high` / `critical` | High-risk evidence | `high_risk` |
| `suspicious` | Suspicious characteristics | `suspicious` |
| `guarded` | Some caution indicators | `caution` |
| `low` | Low observed risk | `low` |
| `insufficient_evidence` / score null | Incomplete assessment | `incomplete` |

## Verification

- 65 unit tests: URL sanitization, response parsing, backend status mapping, timeouts, cache TTL and epochs, single-flight, request gating, messages, contract parity, static privacy/manifest checks, production build.
- `pnpm --filter @phishguard/extension typecheck` and `pnpm lint` pass.
- `google-chrome-stable --pack-extension` validated the built package.
- Docs updated: `docs/chrome-extension.md`, `docs/implementation-roadmap.md`, `docs/architecture.md`, `AGENTS.md`, `.env.example`.