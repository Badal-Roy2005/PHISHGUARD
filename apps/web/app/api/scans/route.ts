import { NextResponse } from "next/server";

import { createClient } from "@/lib/supabase/server";

const SCAN_COLUMNS =
  "id,url,normalized_url,status,risk_score,risk_band,confidence,created_at,completed_at";

export async function GET() {
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
    .eq("user_id", user.id)
    .order("created_at", { ascending: false })
    .limit(50);

  if (error) {
    return NextResponse.json(
      {
        error: {
          code: "upstream_unavailable",
          message: "Scan history is temporarily unavailable.",
        },
      },
      { status: 503 },
    );
  }

  return NextResponse.json({ scans: data ?? [] });
}
