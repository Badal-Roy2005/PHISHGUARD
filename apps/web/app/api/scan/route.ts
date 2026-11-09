import { NextResponse, type NextRequest } from "next/server";

import { createScanResponse } from "@/lib/api/scan";
import { callAnalysis } from "@/lib/analysis";
import { createClient } from "@/lib/supabase/server";

const MAX_BODY_BYTES = 16_384;

function invalidJson(): NextResponse {
  return NextResponse.json(
    { error: { code: "invalid_request", message: "Request body must be valid JSON." } },
    { status: 400 },
  );
}

/**
 * Resolve the authenticated user from the verified server-side session.
 *
 * `supabase.auth.getUser()` validates the session token with Supabase Auth; it
 * never trusts a user id from the request body or from a browser-supplied
 * header. Anonymous callers (no session, or an expired/invalid session) yield
 * `null`, which the analysis service treats as "do not persist".
 */
async function getVerifiedUser(): Promise<{ user: { id: string } | null }> {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  return { user: user ? { id: user.id } : null };
}

export async function POST(request: NextRequest) {
  const raw = await request.text();
  if (raw.length > MAX_BODY_BYTES) {
    return NextResponse.json(
      { error: { code: "payload_too_large", message: "Request body is too large." } },
      { status: 413 },
    );
  }

  let body: unknown;
  try {
    body = JSON.parse(raw) as unknown;
  } catch {
    return invalidJson();
  }

  const requestId = request.headers.get("X-Request-ID") ?? crypto.randomUUID();

  const result = await createScanResponse({
    body,
    getUser: getVerifiedUser,
    analyze: (payload, userId) => callAnalysis(payload, userId, requestId),
  });

  return NextResponse.json(result.body, { status: result.status });
}
