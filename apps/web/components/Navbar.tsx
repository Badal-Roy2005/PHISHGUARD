"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";

interface NavbarProps {
  user: { id: string; email?: string } | null;
}

export default function Navbar({ user }: NavbarProps) {
  const router = useRouter();

  const handleSignOut = () => {
    router.push("/login/actions/signOut");
  };

  return (
    <nav className="border-b border-slate-700 bg-slate-900/90 backdrop-blur-md supports-[backdrop-filter]:bg-slate-900/70">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="flex h-16 items-center justify-between">
          <div className="flex items-center gap-2">
            <Link href="/" className="flex items-center gap-2">
              <span className="flex h-6 w-6 items-center justify-center border-2 border-cyan-400 text-[10px] font-bold uppercase bg-cyan-400 text-slate-950">
                PG
              </span>
              <span className="font-bold text-xl tracking-tighter text-slate-100">
                PHISHGUARD
              </span>
            </Link>
          </div>

          <div className="hidden md:flex items-center gap-6">
            {user ? (
              <div className="flex items-center gap-3">
                <Link
                  href="/account"
                  className="text-sm font-mono text-slate-300 hover:text-cyan-400 transition-colors underline decoration-slate-700/50 hover-decoration-cyan-400"
                >
                  Account
                </Link>
                <button
                  onClick={handleSignOut}
                  className="text-sm font-mono text-slate-300 hover:text-cyan-400 transition-colors underline decoration-slate-700/50 hover-decoration-cyan-400"
                >
                  Sign out
                </button>
              </div>
            ) : (
              <div className="flex items-center gap-3">
                <Link
                  href="/login"
                  className="text-sm font-mono text-slate-300 hover:text-cyan-400 transition-colors underline decoration-slate-700/50 hover-decoration-cyan-400"
                >
                  Sign in
                </Link>
                <Link
                  href="/login"
                  className="text-sm font-mono text-slate-950 bg-cyan-400 border-2 border-cyan-400 px-3 py-1.5 hover:bg-cyan-300 transition-colors"
                >
                  Sign up
                </Link>
              </div>
            )}
          </div>

          <div className="flex items-center gap-2 md:hidden">
            <button
              onClick={() => router.push("/login")}
              className="p-2 border-2 border-slate-600 text-slate-400 hover:text-cyan-400 hover:border-cyan-400 hover:bg-cyan-400/10 transition-colors"
              aria-label="User menu"
            >
              {user ? "👤" : "🔐"}
            </button>
          </div>
        </div>
      </div>
    </nav>
  );
}
