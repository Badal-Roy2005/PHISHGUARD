"use client";

import type { FormEvent } from "react";
import { useState, useEffect, useCallback } from "react";
import { useRouter, useSearchParams } from "next/navigation";

import type { ScanRequest, ScanResult } from "@phishguard/contracts";
import { ScanResultInline } from "@/components/ScanResultInline";

interface ScanFormProps {
  variant?: "hero" | "compact";
  className?: string;
}

function isScanResult(data: unknown): data is ScanResult {
  return (
    typeof data === "object" &&
    data !== null &&
    "risk" in data
  );
}

export function ScanForm({ variant = "hero", className }: ScanFormProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const initialUrlParam = searchParams.get("url");
  const [url, setUrl] = useState(initialUrlParam ?? "");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [autoSubmitted, setAutoSubmitted] = useState(false);

  const runScan = useCallback(
    async (targetUrl: string) => {
      const trimmed = targetUrl.trim();
      if (!trimmed) return;
      setError(null);
      setResult(null);
      setLoading(true);

      try {
        const payload: ScanRequest = {
          url: trimmed,
          options: { include_intel: true, include_ct: false, timeout_ms: 15000 },
        };
        const response = await fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        const text = await response.text();
        const data: unknown = JSON.parse(text);

        if (response.ok && isScanResult(data)) {
          if (variant === "compact") {
            router.push(`/scan?url=${encodeURIComponent(trimmed)}`);
          } else {
            setResult(data);
          }
        } else {
          const msg =
            typeof data === "object" &&
            data !== null &&
            "error" in data &&
            typeof (data as Record<string, unknown>).error === "object" &&
            (data as Record<string, unknown>).error !== null &&
            "message" in ((data as Record<string, unknown>).error as Record<string, unknown>)
              ? ((data as Record<string, unknown>).error as Record<string, unknown>).message as string
              : "Analysis failed";
          setError(msg);
        }
      } catch {
        setError("Network error. Please try again.");
      } finally {
        setLoading(false);
      }
    },
    [variant, router],
  );

  const handleSubmit = useCallback(
    (e: FormEvent<HTMLFormElement>) => {
      e.preventDefault();
      runScan(url);
    },
    [url, runScan],
  );

  useEffect(() => {
    if (initialUrlParam && !autoSubmitted && !loading && !result && !error) {
      setAutoSubmitted(true);
      runScan(initialUrlParam);
    }
  }, [initialUrlParam, autoSubmitted, loading, result, error, runScan]);

  const reset = useCallback(() => {
    setResult(null);
    setError(null);
    setUrl("");
    router.push(window.location.pathname);
  }, [router]);

  if (result && variant === "hero") {
    return (
      <div className={["mt-8 space-y-8 border-2 border-slate-700 bg-slate-900 p-5", className].filter(Boolean).join(" ")}>
        <div className="flex items-center justify-between border-b border-slate-700 pb-3">
          <h2 className="text-lg font-mono font-bold text-cyan-400">Scan result</h2>
          <button
            onClick={reset}
            className="text-sm font-mono text-slate-400 hover:text-cyan-400 underline decoration-slate-700/50 hover-decoration-cyan-400"
          >
            New scan
          </button>
        </div>
        <ScanResultInline scan={result} onNewScan={reset} />
      </div>
    );
  }

  const isCompact = variant === "compact";

  return (
    <div className={["space-y-4", className].filter(Boolean).join(" ")}>
      <form onSubmit={handleSubmit} noValidate className="space-y-3 border-2 border-slate-700 bg-slate-900 p-4">
        <div className="flex gap-2">
          <input
            type="url"
            name="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            required
            disabled={loading}
            autoComplete="off"
            spellCheck={false}
            className={
              "flex-1 border-2 border-slate-600 bg-slate-950 text-slate-100 px-4 py-3 font-mono text-sm placeholder-slate-500 focus:border-cyan-400 focus:outline-none focus:ring-1 focus:ring-cyan-400 disabled:opacity-50 disabled:cursor-not-allowed " +
              (isCompact ? "text-sm py-2.5" : "")
            }
          />
          {loading ? (
            <span className="text-cyan-400 font-mono text-xs animate-pulse">
              SCANNING…
            </span>
          ) : (
            <button
              type="submit"
              disabled={loading || !url.trim()}
              className="border-2 border-cyan-400 bg-cyan-400 text-slate-950 font-mono font-bold text-xs px-4 py-3 hover:bg-cyan-300 transition-colors disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
            >
              {isCompact ? "GO" : "ANALYZE"}
            </button>
          )}
        </div>

        {error && (
          <p className="border-2 border-red-500 bg-red-900/20 text-red-400 px-3 py-2 text-xs font-mono font-bold" role="alert">
            {error}
          </p>
        )}

        {variant === "compact" && (
          <p className="text-[10px] font-mono text-slate-500 uppercase tracking-widest">
            opens full report page
          </p>
        )}
      </form>

      {result && variant === "compact" && (
        <div className="border-2 border-slate-700 bg-slate-900 p-4">
          <p className="text-xs font-mono text-slate-300">
            Scan initiated for <span className="font-mono text-cyan-400">{url}</span>
          </p>
        </div>
      )}
    </div>
  );
}
