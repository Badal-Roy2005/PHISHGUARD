import type { ScanRequest } from "@phishguard/contracts";

import type { AnalysisResult } from "./api/scan.ts";

const ANALYSIS_TIMEOUT_MS = 20_000;

function unavailable(message: string): AnalysisResult {
  return {
    status: 503,
    body: { error: { code: "upstream_unavailable", message } },
  };
}

function parseJson(text: string): unknown {
  if (text === "") {
    return null;
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

export async function callAnalysis(
  payload: ScanRequest,
  userId: string,
  requestId: string,
): Promise<AnalysisResult> {
  const baseUrl = process.env.ANALYSIS_API_URL?.trim();
  const serviceToken = process.env.ANALYSIS_SERVICE_TOKEN?.trim();
  if (!baseUrl || !serviceToken) {
    return unavailable("Analysis service is not configured.");
  }

  let endpoint: string;
  try {
    endpoint = new URL("/internal/analyze", baseUrl).toString();
  } catch {
    return unavailable("Analysis service is not configured.");
  }

  let response: Response;
  try {
    response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Service-Token": serviceToken,
        "X-Authenticated-User-Id": userId,
        "X-Request-ID": requestId,
      },
      body: JSON.stringify(payload),
      cache: "no-store",
      signal: AbortSignal.timeout(ANALYSIS_TIMEOUT_MS),
    });
  } catch {
    return unavailable("Analysis service is temporarily unavailable.");
  }

  const body = parseJson(await response.text());
  if (response.status === 200) {
    return { status: 200, body };
  }
  if (response.status === 400 || response.status === 413 || response.status === 429) {
    return { status: response.status, body };
  }
  if (response.status === 503) {
    return { status: 503, body };
  }
  return unavailable("Analysis service returned an unexpected response.");
}
