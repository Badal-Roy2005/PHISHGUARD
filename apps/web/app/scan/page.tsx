"use client";

import { Suspense } from "react";
import Link from "next/link";

import { ScanForm } from "@/components/ScanForm";

function ScanPageContent() {
  return (
    <main className="mx-auto max-w-3xl px-6 py-12 sm:px-8">
      <Link href="/" className="inline-flex items-center gap-2 mb-6">
        <span className="rounded-lg bg-cyan-500 px-2 py-1 text-xs font-bold text-slate-950">
          PG
        </span>
        <span className="font-bold text-xl tracking-tight text-slate-100">
          PHISHGUARD
        </span>
      </Link>
      <h1 className="mb-2 text-3xl font-bold tracking-tight text-slate-100">
        Scan a URL
      </h1>
      <p className="mb-8 text-slate-400">
        Enter a URL to analyze. Results include deterministic engine findings,
        threat intelligence, TLS/HTTP security posture, and ML probability where
        available.
      </p>
      <ScanForm variant="hero" />
    </main>
  );
}

export default function ScanPage() {
  return (
    <Suspense fallback={<div className="mx-auto max-w-3xl px-6 py-12">Loading…</div>}>
      <ScanPageContent />
    </Suspense>
  );
}
