import { validateScanRequest, type ScanRequest } from "@phishguard/contracts";

export interface AuthenticatedUser {
  id: string;
}

export interface ApiResponse {
  status: number;
  body: unknown;
}

export type AnalysisResult = ApiResponse;

export interface CreateScanDependencies {
  body: unknown;
  getUser: () => Promise<{ user: AuthenticatedUser | null }>;
  analyze: (payload: ScanRequest, userId: string) => Promise<AnalysisResult>;
}

function error(status: number, code: string, message: string, details?: unknown): ApiResponse {
  return {
    status,
    body: {
      error: {
        code,
        message,
        ...(details === undefined ? {} : { details }),
      },
    },
  };
}

export async function createScanResponse({
  body,
  getUser,
  analyze,
}: CreateScanDependencies): Promise<ApiResponse> {
  let user: AuthenticatedUser | null;
  try {
    ({ user } = await getUser());
  } catch {
    return error(503, "upstream_unavailable", "Authentication is temporarily unavailable.");
  }

  if (!user) {
    return error(401, "unauthorized", "Authentication required.");
  }

  const parsed = validateScanRequest(body);
  if (!parsed.ok) {
    return error(400, "invalid_request", "Request validation failed.", {
      errors: parsed.errors,
    });
  }

  try {
    return await analyze(parsed.value, user.id);
  } catch {
    return error(503, "upstream_unavailable", "Analysis is temporarily unavailable.");
  }
}
