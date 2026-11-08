import { NextResponse, type NextRequest } from "next/server";

import { safeNextPath } from "@/lib/security";
import { createClient } from "@/lib/supabase/server";

export async function GET(request: NextRequest) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const next = safeNextPath(url.searchParams.get("next"));

  if (!code) {
    return NextResponse.redirect(new URL("/login?error=Missing%20auth%20code", url));
  }

  const supabase = await createClient();
  const { error } = await supabase.auth.exchangeCodeForSession(code);
  if (error) {
    return NextResponse.redirect(new URL("/login?error=Could%20not%20confirm%20session", url));
  }

  return NextResponse.redirect(new URL(next, url));
}
