import assert from "node:assert/strict";
import { test } from "node:test";

import { createServerClient } from "@supabase/ssr";

/**
 * Live M9 persistence regression test.
 *
 * Requires a running web server (calling a running analysis service configured
 * with PERSISTENCE=supabase) plus the Supabase project credentials. It is
 * skipped by default so `pnpm test` stays hermetic.
 *
 * Enable with `M9_INTEGRATION=1` and:
 *   SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, NEXT_PUBLIC_SUPABASE_ANON_KEY,
 *   WEB_BASE_URL (default http://localhost:3000)
 *
 * It creates two disposable users and removes them (and their scans) in a
 * `finally` block. Never point it at production data.
 */

const enabled = process.env.M9_INTEGRATION === "1";

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`missing required env var: ${name}`);
  }
  return value;
}

interface ScanRow {
  id: string;
  user_id: string | null;
}

interface DisposableUser {
  id: string;
  email: string;
  password: string;
}

test(
  "live: anonymous, authenticated, forged identity, and expired session",
  { skip: !enabled && "set M9_INTEGRATION=1 with Supabase + web env" },
  async () => {
    const supabaseUrl = required("SUPABASE_URL").replace(/\/$/, "");
    const serviceKey = required("SUPABASE_SERVICE_ROLE_KEY");
    const anonKey = required("NEXT_PUBLIC_SUPABASE_ANON_KEY");
    const webBase = (process.env.WEB_BASE_URL ?? "http://localhost:3000").replace(/\/$/, "");

    const serviceHeaders: Record<string, string> = {
      apikey: serviceKey,
      Authorization: `Bearer ${serviceKey}`,
      "Content-Type": "application/json",
    };

    const stamp = `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
    const created: DisposableUser[] = [];

    async function createUser(tag: string): Promise<DisposableUser> {
      const email = `m9.1.${tag}.${stamp}@example.com`;
      const password = `M9-1-${stamp}-${tag}-Passw0rd!`;
      const response = await fetch(`${supabaseUrl}/auth/v1/admin/users`, {
        method: "POST",
        headers: serviceHeaders,
        body: JSON.stringify({ email, password, email_confirm: true }),
      });
      const payload = (await response.json()) as { id?: string; msg?: string; message?: string };
      if (!response.ok || !payload.id) {
        throw new Error(`create user ${tag} failed: ${response.status} ${payload.msg ?? payload.message ?? ""}`);
      }
      const user: DisposableUser = { id: payload.id, email, password };
      created.push(user);
      return user;
    }

    async function cookieFor(user: DisposableUser): Promise<string> {
      const jar: Record<string, string> = {};
      const client = createServerClient(supabaseUrl, anonKey, {
        cookies: {
          getAll: () => Object.entries(jar).map(([name, value]) => ({ name, value })),
          setAll: (cookies) => {
            for (const { name, value } of cookies) {
              jar[name] = value;
            }
          },
        },
      });
      const { error } = await client.auth.signInWithPassword({
        email: user.email,
        password: user.password,
      });
      if (error) {
        throw new Error(`sign in failed for ${user.email}: ${error.message}`);
      }
      return Object.entries(jar)
        .map(([name, value]) => `${name}=${value}`)
        .join("; ");
    }

    async function scansOf(userId: string): Promise<ScanRow[]> {
      const response = await fetch(
        `${supabaseUrl}/rest/v1/scans?select=id,user_id&user_id=eq.${userId}`,
        { headers: serviceHeaders },
      );
      return (await response.json()) as ScanRow[];
    }

    async function scanCount(): Promise<number> {
      const response = await fetch(`${supabaseUrl}/rest/v1/scans?select=id`, {
        headers: serviceHeaders,
      });
      return ((await response.json()) as ScanRow[]).length;
    }

    async function postScan(
      body: unknown,
      cookie?: string,
      extraHeaders: Record<string, string> = {},
    ): Promise<{ status: number; body: unknown }> {
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
        ...extraHeaders,
      };
      if (cookie) {
        headers["Cookie"] = cookie;
      }
      const response = await fetch(`${webBase}/api/scan`, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
      });
      const text = await response.text();
      let parsed: unknown = null;
      try {
        parsed = JSON.parse(text) as unknown;
      } catch {
        parsed = text;
      }
      return { status: response.status, body: parsed };
    }

    const scanBody = {
      url: "https://example.com",
      options: { include_intel: false, include_ct: false, timeout_ms: 5000 },
    };

    try {
      const userA = await createUser("a");
      const userB = await createUser("b");
      const cookieA = await cookieFor(userA);
      const cookieB = await cookieFor(userB);

      // 1. Anonymous scan works and persists nothing.
      const beforeAnon = await scanCount();
      const anon = await postScan(scanBody);
      assert.equal(anon.status, 200, "anonymous scan should succeed");
      assert.equal(await scanCount(), beforeAnon, "anonymous scan must not persist");

      // 2. Authenticated scan persists exactly one row owned by A.
      const beforeAuth = (await scansOf(userA.id)).length;
      const auth = await postScan(scanBody, cookieA);
      assert.equal(auth.status, 200, "authenticated scan should succeed");
      const rowsA = await scansOf(userA.id);
      assert.equal(rowsA.length, beforeAuth + 1, "exactly one row should be persisted for A");
      const scanId = rowsA[rowsA.length - 1]?.id;
      assert.ok(scanId, "persisted scan id is required");

      // 3. Detail access: owner 200, other user 404.
      const detailA = await fetch(`${webBase}/api/scans/${scanId}`, { headers: { Cookie: cookieA } });
      assert.equal(detailA.status, 200, "owner should read the scan");
      const detailB = await fetch(`${webBase}/api/scans/${scanId}`, { headers: { Cookie: cookieB } });
      assert.equal(detailB.status, 404, "other user must not read the scan");
      const pageA = await fetch(`${webBase}/scan/${scanId}`, { headers: { Cookie: cookieA } });
      assert.equal(pageA.status, 200, "owner detail page should render");
      const pageB = await fetch(`${webBase}/scan/${scanId}`, { headers: { Cookie: cookieB } });
      assert.equal(pageB.status, 404, "other user detail page must be 404");

      // 4. A forged user id in the body cannot impersonate B.
      const beforeForgedBody = await scansOf(userB.id);
      const forgedBody = await postScan({ ...scanBody, user_id: userB.id }, cookieA);
      assert.equal(forgedBody.status, 400, "unknown user_id field must be rejected");
      assert.deepEqual(await scansOf(userB.id), beforeForgedBody, "B must gain no rows");

      // 5. A forged identity header cannot impersonate B.
      const beforeForgedHeader = await scansOf(userB.id);
      const forgedHeaderAsA = await postScan(scanBody, cookieA, {
        "X-Authenticated-User-Id": userB.id,
      });
      assert.equal(forgedHeaderAsA.status, 200);
      assert.equal((await scansOf(userA.id)).length, rowsA.length + 1, "row must belong to verified A");
      assert.deepEqual(await scansOf(userB.id), beforeForgedHeader, "B must gain no rows");

      const beforeAnonHeader = await scanCount();
      const forgedHeaderAnon = await postScan(scanBody, undefined, {
        "X-Authenticated-User-Id": userB.id,
      });
      assert.equal(forgedHeaderAnon.status, 200);
      assert.equal(await scanCount(), beforeAnonHeader, "forged header while anonymous must not persist");

      // 6. Invalid/expired session never persists an authenticated row.
      const projectRef = new URL(supabaseUrl).hostname.split(".")[0];
      const bogusPayload = encodeURIComponent(
        JSON.stringify({
          access_token: "invalid-session-token",
          refresh_token: "invalid-session-token",
          expires_at: 1,
          token_type: "bearer",
        }),
      );
      const beforeExpired = await scanCount();
      const expired = await postScan(scanBody, `sb-${projectRef}-auth-token=${bogusPayload}`);
      assert.ok(
        [200, 401, 503].includes(expired.status),
        `expired session returned unexpected status ${expired.status}`,
      );
      assert.equal(await scanCount(), beforeExpired, "expired session must not persist");
    } finally {
      for (const user of created) {
        await fetch(`${supabaseUrl}/rest/v1/scans?user_id=eq.${user.id}`, {
          method: "DELETE",
          headers: serviceHeaders,
        });
        await fetch(`${supabaseUrl}/auth/v1/admin/users/${user.id}`, {
          method: "DELETE",
          headers: serviceHeaders,
        });
      }
    }
  },
);
