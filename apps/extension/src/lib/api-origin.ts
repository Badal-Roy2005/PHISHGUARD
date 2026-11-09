/**
 * Resolve the approved backend origin from the manifest.
 *
 * The build injects exactly one host permission. The service worker derives its
 * request origin from that permission instead of accepting an endpoint from a
 * message, so a compromised popup message cannot redirect browsing data.
 */

export function resolveApiOrigin(hostPermissions: unknown): string | null {
  if (!Array.isArray(hostPermissions) || hostPermissions.length !== 1) {
    return null;
  }
  const entry = hostPermissions[0];
  if (typeof entry !== "string" || !entry.endsWith("/*")) {
    return null;
  }

  let url: URL;
  try {
    url = new URL(entry.slice(0, -2));
  } catch {
    return null;
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return null;
  }
  if (url.username !== "" || url.password !== "") {
    return null;
  }
  if (url.pathname !== "/" || url.search !== "" || url.hash !== "") {
    return null;
  }
  if (url.hostname === "" || url.hostname.includes("*")) {
    return null;
  }

  return url.origin;
}

export function scanEndpoint(origin: string): string | null {
  let url: URL;
  try {
    url = new URL("/api/scan", origin);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return null;
  }
  if (url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "") {
    return null;
  }
  return url.toString();
}
