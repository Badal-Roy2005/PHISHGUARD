import Link from "next/link";
import { redirect } from "next/navigation";

import { createClient } from "@/lib/supabase/server";

import { signOut } from "../login/actions.ts";

export default async function AccountPage() {
  const supabase = await createClient();
  const {
    data: { user },
    error: authError,
  } = await supabase.auth.getUser();

  if (authError || !user) {
    redirect("/login?next=/account");
  }

  const [profileResult, scansResult] = await Promise.all([
    supabase
      .from("profiles")
      .select("email,display_name,role,created_at")
      .eq("id", user.id)
      .maybeSingle(),
    supabase
      .from("scans")
      .select("id,url,normalized_url,status,risk_score,risk_band,confidence,created_at,completed_at")
      .eq("user_id", user.id)
      .order("created_at", { ascending: false })
      .limit(50),
  ]);

  const profile = profileResult.data;
  const scans = scansResult.data ?? [];

  return (
    <main className="mx-auto max-w-3xl px-6 py-16">
      <div className="flex items-center justify-between">
        <Link href="/" className="text-xs uppercase tracking-[0.2em] text-cyan-400">
          PHISHGUARD
        </Link>
        <form action={signOut}>
          <button className="text-sm text-slate-400 hover:text-slate-200" type="submit">
            Sign out
          </button>
        </form>
      </div>

      <h1 className="mt-6 text-3xl font-semibold tracking-tight">Account</h1>
      <dl className="mt-6 grid gap-3 rounded-lg border border-slate-800 p-4 text-sm sm:grid-cols-3">
        <div>
          <dt className="text-xs uppercase tracking-wider text-slate-500">Email</dt>
          <dd className="mt-1 text-slate-200">{profile?.email ?? user.email ?? "Not set"}</dd>
        </div>
        <div>
          <dt className="text-xs uppercase tracking-wider text-slate-500">Display name</dt>
          <dd className="mt-1 text-slate-200">{profile?.display_name ?? "Not set"}</dd>
        </div>
        <div>
          <dt className="text-xs uppercase tracking-wider text-slate-500">Role</dt>
          <dd className="mt-1 text-slate-200">{profile?.role ?? "user"}</dd>
        </div>
      </dl>

      {profileResult.error || scansResult.error ? (
        <p className="mt-6 rounded-lg border border-amber-900 bg-amber-950/40 px-4 py-3 text-sm text-amber-200">
          Some account data is temporarily unavailable. Missing data is not treated as empty
          history.
        </p>
      ) : null}

      <section className="mt-10">
        <h2 className="text-sm font-medium uppercase tracking-wider text-slate-400">
          Private scan history
        </h2>
        {scans.length === 0 ? (
          <p className="mt-3 text-sm text-slate-500">No persisted scans yet.</p>
        ) : (
          <ul className="mt-3 divide-y divide-slate-800 rounded-lg border border-slate-800">
            {scans.map((scan) => (
              <li key={scan.id} className="px-4 py-3 text-sm">
                <div className="flex items-center justify-between gap-4">
                  <span className="truncate font-mono text-xs text-slate-300">
                    {scan.normalized_url}
                  </span>
                  <span className="shrink-0 text-slate-400">
                    {scan.risk_band ?? scan.status}
                    {scan.risk_score === null ? "" : ` · ${scan.risk_score}`}
                  </span>
                </div>
                <p className="mt-1 text-xs text-slate-500">
                  {scan.status} · {new Date(scan.created_at).toLocaleString()}
                </p>
              </li>
            ))}
          </ul>
        )}
      </section>
    </main>
  );
}
