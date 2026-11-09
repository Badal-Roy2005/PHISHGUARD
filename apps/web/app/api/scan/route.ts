import { NextResponse, type NextRequest } from "next/server";

import { callAnalysis } from "@/lib/analysis";
import type { ScanRequest } from "@phishguard/contracts";

const MAX_BODY_BYTES = 16_384;

function invalidJson(): NextResponse {
  return NextResponse.json(
    { error: { code: "invalid_request", message: "Request body must be valid JSON." } },
    { status: 400 },
  );
}

function isScanRequest(obj: unknown): obj is ScanRequest {
  return (
    typeof obj === "object" &&
    obj !== null &&
    "url" in obj &&
    typeof (obj as Record<string, unknown>).url === "string" &&
    ((obj as Record<string, unknown>).url as string).length > 0
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

  if (!isScanRequest(body)) {
    return NextResponse.json(
      { error: { code: "invalid_request", message: "Invalid scan request." } },
      { status: 400 },
    );
  }

  const requestId = request.headers.get("X-Request-ID") ?? crypto.randomUUID();

  const result = await callAnalysis(
    body,
    "",
    requestId,
  );

  return NextResponse.json(result.body, { status: result.status });
}