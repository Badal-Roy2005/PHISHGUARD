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
    <main className="min-h-screen flex items-center justify-center bg-slate-950 text-white px-4 py-12">
      <div className="mx-auto max-w-md w-full">
        <div className="text-center mb-10">
          <Link href="/" className="inline-flex items-center gap-2">
            <span className="border-2 border-cyan-400 text-slate-950 font-mono font-bold text-[10px] uppercase bg-cyan-400 px-2 py-1">
              PG
            </span>
            <span className="font-mono font-bold text-xl text-slate-100 tracking-tighter">
              PHISHGUARD
            </span>
          </Link>
        </div>

        <div className="border-2 border-slate-700 bg-slate-900 p-6">
          <h1 className="mb-1 text-2xl font-mono font-bold text-slate-100">
            Sign in
          </h1>
          <p className="mt-2 text-[11px] font-mono text-slate-400">
            Your scan history is private. Sign in to access your account.
          </p>

          {error ? (
            <p className="mt-6 mb-4 border-2 border-red-500 bg-red-900/20 text-red-400 px-3 py-2 text-[11px] font-mono font-bold">
              {error}
            </p>
          ) : null}
          {message ? (
            <p className="mt-6 mb-4 border-2 border-cyan-400/20 bg-slate-900 text-cyan-300 px-3 py-2 text-[11px] font-mono">
              {message}
            </p>
          ) : null}

          <form action={signIn} className="mt-8 space-y-4" noValidate>
            <input type="hidden" name="next" value={next} />
            <div className="space-y-2">
              <label className="block">
                <span className="block text-[11px] font-mono text-slate-300 mb-1">
                  Email address
                </span>
                <input
                  name="email"
                  type="email"
                  autoComplete="email"
                  required
                  className="w-full border-2 border-slate-600 bg-slate-950 text-slate-100 px-4 py-3 font-mono text-sm placeholder-slate-500 focus:border-cyan-400 focus:outline-none focus:ring-1 focus:ring-cyan-400"
                />
              </label>
              <label className="block">
                <span className="block text-[11px] font-mono text-slate-300 mb-1">
                  Password
                </span>
                <input
                  name="password"
                  type="password"
                  autoComplete="current-password"
                  minLength={8}
                  required
                  className="w-full border-2 border-slate-600 bg-slate-950 text-slate-100 px-4 py-3 font-mono text-sm placeholder-slate-500 focus:border-cyan-400 focus:outline-none focus:ring-1 focus:ring-cyan-400"
                />
              </label>
            </div>
            <button
              type="submit"
              className="w-full border-2 border-cyan-400 bg-cyan-400 text-slate-950 font-mono font-bold text-xs px-4 py-2 hover:bg-cyan-300 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Sign in
            </button>
          </form>

          <div className="mt-10 pt-6 border-t-2 border-slate-800">
            <h2 className="mb-4 text-[10px] font-mono font-bold text-slate-400 uppercase tracking-widest">
              Create an account
            </h2>
            <form action={signUp} className="space-y-4" noValidate>
              <input type="hidden" name="next" value={next} />
              <div className="space-y-2">
                <label className="block">
                  <span className="block text-[11px] font-mono text-slate-300 mb-1">
                    Display name (optional)
                  </span>
                  <input
                    name="display_name"
                    type="text"
                    autoComplete="nickname"
                    maxLength={80}
                    className="w-full border-2 border-slate-600 bg-slate-950 text-slate-100 px-4 py-3 font-mono text-sm placeholder-slate-500 focus:border-cyan-400 focus:outline-none focus:ring-1 focus:ring-cyan-400"
                  />
                </label>
                <label className="block">
                  <span className="block text-[11px] font-mono text-slate-300 mb-1">
                    Email address
                  </span>
                  <input
                    name="email"
                    type="email"
                    autoComplete="email"
                    required
                    className="w-full border-2 border-slate-600 bg-slate-950 text-slate-100 px-4 py-3 font-mono text-sm placeholder-slate-500 focus:border-cyan-400 focus:outline-none focus:ring-1 focus:ring-cyan-400"
                  />
                </label>
                <label className="block">
                  <span className="block text-[11px] font-mono text-slate-300 mb-1">
                    Password
                  </span>
                  <input
                    name="password"
                    type="password"
                    autoComplete="new-password"
                    minLength={8}
                    required
                    className="w-full border-2 border-slate-600 bg-slate-950 text-slate-100 px-4 py-3 font-mono text-sm placeholder-slate-500 focus:border-cyan-400 focus:outline-none focus:ring-1 focus:ring-cyan-400"
                  />
                </label>
              </div>
              <button
                type="submit"
                className="w-full border-2 border-cyan-400 bg-cyan-400 text-slate-950 font-mono font-bold text-xs px-4 py-2 hover:bg-cyan-300 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Create account
              </button>
            </form>
          </div>

          <p className="mt-10 text-center text-[11px] font-mono text-slate-500">
            Already have an account?{" "}
            <Link href="/login" className="text-cyan-400 hover:text-cyan-300 underline decoration-cyan-400/50 hover-decoration-cyan-400">
              Sign in
            </Link>
          </p>
        </div>
      </div>
    </main>
  );
}
