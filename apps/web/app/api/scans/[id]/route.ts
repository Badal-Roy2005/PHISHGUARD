import { NextResponse } from "next/server";

import { isUuid } from "@/lib/security";
import { createClient } from "@/lib/supabase/server";

const SCAN_COLUMNS =
  "id,url,normalized_url,status,risk_score,risk_band,confidence,policy_version,result,created_at,completed_at";

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  if (!isUuid(id)) {
    return NextResponse.json(
      { error: { code: "not_found", message: "Scan not found." } },
      { status: 404 },
    );
  }

  const supabase = await createClient();
  const {
    data: { user },
    error: authError,
  } = await supabase.auth.getUser();

  if (authError || !user) {
    return NextResponse.json(
      { error: { code: "unauthorized", message: "Authentication required." } },
      { status: 401 },
    );
  }

  const { data, error } = await supabase
    .from("scans")
    .select(SCAN_COLUMNS)
    .eq("id", id)
    .eq("user_id", user.id)
    .maybeSingle();

  if (error) {
    return NextResponse.json(
      {
        error: {
          code: "upstream_unavailable",
          message: "Scan is temporarily unavailable.",
        },
      },
      { status: 503 },
    );
  }

  if (!data) {
    return NextResponse.json(
      { error: { code: "not_found", message: "Scan not found." } },
      { status: 404 },
    );
  }

  return NextResponse.json({ scan: data });
}
