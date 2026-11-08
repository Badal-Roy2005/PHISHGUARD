import Link from "next/link";

import { safeNextPath } from "@/lib/security";

import { signIn, signUp } from "./actions.ts";

interface LoginPageProps {
  searchParams: Promise<{
    error?: string;
    message?: string;
    next?: string;
  }>;
}

export default async function LoginPage({ searchParams }: LoginPageProps) {
  const params = await searchParams;
  const next = safeNextPath(params.next);
  const error = params.error?.slice(0, 300);
  const message = params.message?.slice(0, 300);

  return (
    <main className="mx-auto max-w-md px-6 py-16">
      <Link href="/" className="text-xs uppercase tracking-[0.2em] text-cyan-400">
        PHISHGUARD
      </Link>
      <h1 className="mt-3 text-3xl font-semibold tracking-tight">Sign in</h1>
      <p className="mt-2 text-sm text-slate-400">
        Your scan history is private. Authentication is required for scans and account data.
      </p>

      {error ? (
        <p className="mt-6 rounded-lg border border-red-900 bg-red-950/40 px-4 py-3 text-sm text-red-200">
          {error}
        </p>
      ) : null}
      {message ? (
        <p className="mt-6 rounded-lg border border-cyan-900 bg-cyan-950/40 px-4 py-3 text-sm text-cyan-200">
          {message}
        </p>
      ) : null}

      <form action={signIn} className="mt-8 space-y-4">
        <input type="hidden" name="next" value={next} />
        <label className="block text-sm">
          <span className="text-slate-300">Email</span>
          <input
            className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-slate-100"
            name="email"
            type="email"
            autoComplete="email"
            required
          />
        </label>
        <label className="block text-sm">
          <span className="text-slate-300">Password</span>
          <input
            className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-slate-100"
            name="password"
            type="password"
            autoComplete="current-password"
            minLength={8}
            required
          />
        </label>
        <button
          className="w-full rounded-lg bg-cyan-500 px-4 py-2 font-medium text-slate-950"
          type="submit"
        >
          Sign in
        </button>
      </form>

      <section className="mt-10 border-t border-slate-800 pt-8">
        <h2 className="text-sm font-medium uppercase tracking-wider text-slate-400">
          Create an account
        </h2>
        <form action={signUp} className="mt-4 space-y-4">
          <input type="hidden" name="next" value={next} />
          <label className="block text-sm">
            <span className="text-slate-300">Display name (optional)</span>
            <input
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-slate-100"
              name="display_name"
              type="text"
              autoComplete="nickname"
              maxLength={80}
            />
          </label>
          <label className="block text-sm">
            <span className="text-slate-300">Email</span>
            <input
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-slate-100"
              name="email"
              type="email"
              autoComplete="email"
              required
            />
          </label>
          <label className="block text-sm">
            <span className="text-slate-300">Password</span>
            <input
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-slate-100"
              name="password"
              type="password"
              autoComplete="new-password"
              minLength={8}
              required
            />
          </label>
          <button
            className="w-full rounded-lg border border-slate-700 px-4 py-2 font-medium text-slate-100"
            type="submit"
          >
            Create account
          </button>
        </form>
      </section>
    </main>
  );
}
