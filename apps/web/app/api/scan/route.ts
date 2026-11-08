import { NextResponse, type NextRequest } from "next/server";

import { callAnalysis } from "@/lib/analysis";
import { createScanResponse } from "@/lib/api/scan";
import { createClient } from "@/lib/supabase/server";

const MAX_BODY_BYTES = 16_384;

function invalidJson(): NextResponse {
  return NextResponse.json(
    { error: { code: "invalid_request", message: "Request body must be valid JSON." } },
    { status: 400 },
  );
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
    getUser: async () => {
      const supabase = await createClient();
      const {
        data: { user },
      } = await supabase.auth.getUser();
      return { user: user ? { id: user.id } : null };
    },
    analyze: (payload, userId) => callAnalysis(payload, userId, requestId),
  });

  return NextResponse.json(result.body, { status: result.status });
}
