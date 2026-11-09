import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";

import type { Database } from "./database.types.ts";

function isProtectedPath(pathname: string): boolean {
  // Scan submission (/api/scan) is intentionally public: anonymous scans are
  // allowed but never persisted. Identity for persistence is resolved inside
  // the route from the verified Supabase session, never from client input.
  return pathname.startsWith("/account") || pathname.startsWith("/api/scans");
}

function isApiPath(pathname: string): boolean {
  return pathname.startsWith("/api/");
}

function unauthorizedResponse(request: NextRequest): NextResponse {
  if (isApiPath(request.nextUrl.pathname)) {
    return NextResponse.json(
      { error: { code: "unauthorized", message: "Authentication required." } },
      { status: 401 },
    );
  }
  const loginUrl = request.nextUrl.clone();
  loginUrl.pathname = "/login";
  loginUrl.search = "";
  loginUrl.searchParams.set("next", request.nextUrl.pathname);
  return NextResponse.redirect(loginUrl);
}

export async function updateSession(request: NextRequest): Promise<NextResponse> {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL?.trim();
  const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY?.trim();

  if (!supabaseUrl || !supabaseAnonKey) {
    if (isProtectedPath(request.nextUrl.pathname)) {
      if (isApiPath(request.nextUrl.pathname)) {
        return NextResponse.json(
          {
            error: {
              code: "upstream_unavailable",
              message: "Authentication is not configured.",
            },
          },
          { status: 503 },
        );
      }
      const loginUrl = request.nextUrl.clone();
      loginUrl.pathname = "/login";
      loginUrl.search = "";
      loginUrl.searchParams.set("error", "Authentication is not configured.");
      return NextResponse.redirect(loginUrl);
    }
    return NextResponse.next({ request });
  }

  let response = NextResponse.next({ request });

  const supabase = createServerClient<Database>(supabaseUrl, supabaseAnonKey, {
    cookies: {
      getAll() {
        return request.cookies.getAll();
      },
      setAll(cookiesToSet) {
        cookiesToSet.forEach(({ name, value }) => {
          request.cookies.set(name, value);
        });
        response = NextResponse.next({ request });
        cookiesToSet.forEach(({ name, value, options }) => {
          response.cookies.set(name, value, options);
        });
      },
    },
  });

  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user && isProtectedPath(request.nextUrl.pathname)) {
    return unauthorizedResponse(request);
  }

  if (user && request.nextUrl.pathname === "/login") {
    const accountUrl = request.nextUrl.clone();
    accountUrl.pathname = "/account";
    accountUrl.search = "";
    return NextResponse.redirect(accountUrl);
  }

  return response;
}
