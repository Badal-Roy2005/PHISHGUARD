"use server";

import { headers } from "next/headers";
import { redirect } from "next/navigation";

import { optionalPublicEnv } from "@/lib/env";
import { safeNextPath } from "@/lib/security";
import { createClient } from "@/lib/supabase/server";

function loginRedirect(next: string, key: "error" | "message", value: string): never {
  const params = new URLSearchParams({ [key]: value, next });
  redirect(`/login?${params.toString()}`);
}

async function createClientOrRedirect(next: string) {
  let supabase: Awaited<ReturnType<typeof createClient>>;
  try {
    supabase = await createClient();
  } catch {
    loginRedirect(next, "error", "Authentication is not configured.");
  }
  return supabase;
}

export async function signIn(formData: FormData): Promise<void> {
  const email = String(formData.get("email") ?? "").trim();
  const password = String(formData.get("password") ?? "");
  const next = safeNextPath(formData.get("next"));

  if (!email || password.length < 8) {
    loginRedirect(next, "error", "Enter a valid email and a password of at least 8 characters.");
  }

  const supabase = await createClientOrRedirect(next);
  const { error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) {
    loginRedirect(next, "error", "Invalid email or password.");
  }

  redirect(next);
}

export async function signUp(formData: FormData): Promise<void> {
  const email = String(formData.get("email") ?? "").trim();
  const password = String(formData.get("password") ?? "");
  const displayName = String(formData.get("display_name") ?? "").trim();
  const next = safeNextPath(formData.get("next"));

  if (!email || password.length < 8) {
    loginRedirect(next, "error", "Enter a valid email and a password of at least 8 characters.");
  }
  if (displayName.length > 80) {
    loginRedirect(next, "error", "Display name must be 80 characters or fewer.");
  }

  const requestHeaders = await headers();
  const origin =
    optionalPublicEnv("NEXT_PUBLIC_SITE_URL") ??
    requestHeaders.get("origin") ??
    "http://localhost:3000";
  const emailRedirectTo = `${origin}/auth/callback?next=${encodeURIComponent(next)}`;

  const supabase = await createClientOrRedirect(next);
  const { data, error } = await supabase.auth.signUp({
    email,
    password,
    options: {
      emailRedirectTo,
      data: displayName ? { display_name: displayName } : {},
    },
  });

  if (error) {
    loginRedirect(next, "error", "Could not create the account.");
  }
  if (data.session) {
    redirect(next);
  }

  loginRedirect(next, "message", "Check your email to confirm your account.");
}

export async function signOut(): Promise<void> {
  const supabase = await createClient();
  await supabase.auth.signOut();
  redirect("/login");
}
