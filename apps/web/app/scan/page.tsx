"use client";

import type { FormEvent } from "react";
import { useState, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";

import type { ScanRequest, ScanResult, ScanAccepted } from "@phishguard/contracts";

import { ScanResultInline } from "@/components/ScanResultInline";

type ScanResponse = ScanResult | ScanAccepted;

interface ErrorResponse {
  error: {
    code: string;
    message: string;
  };
}

function isScanResult(data: ScanResponse): data is ScanResult {
  return "risk" in data;
}

function isErrorResponse(data: unknown): data is ErrorResponse {
  return (
    typeof data === "object" &&
    data !== null &&
    "error" in data &&
    typeof (data as Record<string, unknown>).error === "object" &&
    (data as Record<string, unknown>).error !== null &&
    "code" in ((data as Record<string, unknown>).error as Record<string, unknown>) &&
    "message" in ((data as Record<string, unknown>).error as Record<string, unknown>)
  );
}

function parseScanResponse(text: string): ScanResponse {
  const parsed: unknown = JSON.parse(text);
  return parsed as ScanResponse;
}

function ScanPageContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const initialUrl = searchParams.get("url");
  if (initialUrl) {
    setUrl(initialUrl);
  }

  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError(null);
    setResult(null);
    setLoading(true);

    try {
      const payload: ScanRequest = {
        url,
        options: { include_intel: true, include_ct: false, timeout_ms: 15000 },
      };
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const text = await response.text();
      const data: ScanResponse = parseScanResponse(text);

      if (response.ok) {
        if (isScanResult(data)) {
          setResult(data);
        } else if (data.scan_id && data.status === "queued") {
          const scanId: string = data.scan_id;
          const scanUrl: string = `/scan/${scanId}`;
          router.push(scanUrl);
        } else {
          setError("Unexpected response from analysis service.");
        }
      } else {
        const msg = isErrorResponse(data)
          ? data.error.message
          : "Analysis failed";
        setError(msg);
      }
    } catch {
      setError("Network error. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  if (result) {
    return <ScanResultInline scan={result} onNewScan={() => setResult(null)} />;
  }

  return (
    <main className="mx-auto max-w-3xl px-6 py-16">
      <Link href="/" className="text-xs uppercase tracking-[0.2em] text-cyan-400">
        PHISHGUARD
      </Link>
      <h1 className="mt-3 text-3xl font-semibold tracking-tight">Scan a URL</h1>
      <p className="mt-2 text-sm text-slate-400">
        Enter a URL to analyze. Results include deterministic engine findings, threat intelligence,
        TLS/HTTP security posture, and ML probability where available.
      </p>

      <form onSubmit={handleSubmit} className="mt-8 space-y-4" noValidate>
        <label className="block text-sm">
          <span className="text-slate-300">URL to analyze</span>
          <input
            className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-slate-100 placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            type="url"
            name="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com/login"
            required
            disabled={loading}
            autoComplete="url"
          />
        </label>

        <div className="flex items-center gap-4">
          <button
            type="submit"
            disabled={loading || !url.trim()}
            className="flex-1 rounded-lg bg-cyan-500 px-4 py-2 font-medium text-slate-950 hover:bg-cyan-400 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? "Analyzing…" : "Analyze"}
          </button>
        </div>

        {error && (
          <p className="rounded-lg border border-red-900 bg-red-950/40 px-4 py-3 text-sm text-red-200" role="alert">
            {error}
          </p>
        )}
      </form>

      <section className="mt-10">
        <h2 className="text-sm font-medium uppercase tracking-wider text-slate-400">
          How it works
        </h2>
        <ul className="mt-3 space-y-2 text-sm text-slate-400">
          <li className="flex gap-3">
            <span className="shrink-0 text-cyan-400">1</span>
            <span>URL structure and lexical analysis (M3)</span>
          </li>
          <li className="flex gap-3">
            <span className="shrink-0 text-cyan-400">2</span>
            <span>Live fetch with DNS pinning, TLS capture, redirect validation (M4/M6)</span>
          </li>
          <li className="flex gap-3">
            <span className="shrink-0 text-cyan-400">3</span>
            <span>Threat intelligence lookups (Google Safe Browsing, URLhaus) (M5B)</span>
          </li>
          <li className="flex gap-3">
            <span className="shrink-0 text-cyan-400">4</span>
            <span>Deterministic risk aggregation with coverage-aware scoring (M7)</span>
          </li>
          <li className="flex gap-3">
            <span className="shrink-0 text-cyan-400">5</span>
            <span>ML phishing probability reported separately, never merged into heuristic score</span>
          </li>
        </ul>
      </section>
    </main>
  );
}

export default function ScanPage() {
  return (
    <Suspense fallback={<div className="mx-auto max-w-3xl px-6 py-16">Loading…</div>}>
      <ScanPageContent />
    </Suspense>
  );
}