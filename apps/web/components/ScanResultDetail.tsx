"use client";

import type { ScanResult } from "@phishguard/contracts";

import { RiskAssessmentSection } from "@/components/scan/RiskAssessmentSection";
import { EngineReportsSection } from "@/components/scan/EngineReportsSection";
import { ExplanationSection } from "@/components/scan/ExplanationSection";
import { EvidenceSection } from "@/components/scan/EvidenceSection";

import { formatDate, formatDuration, bandColor } from "@/lib/ui-utils";

interface ScanResultDetailProps {
  scan: ScanResult;
}

export function ScanResultDetail({ scan }: ScanResultDetailProps) {
  const risk = scan.risk;
  const engines = scan.engines;
  const isPartial = scan.status === "partial";

  return (
    <article className="space-y-8">
      <section className="rounded-lg border border-slate-800 bg-slate-900/40 p-6">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0 flex-1">
            <p className="text-xs uppercase tracking-wider text-slate-500">Target URL</p>
            <p className="mt-1 font-mono text-sm text-slate-200 truncate">{scan.normalized_url}</p>
            {scan.url !== scan.normalized_url && (
              <p className="mt-1 text-xs text-slate-500 truncate">Submitted: {scan.url}</p>
            )}
            <div className="mt-3 flex flex-wrap items-center gap-3 text-sm">
              <span className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 border border-slate-700 bg-slate-900/40 text-slate-300">
                Scan ID: <code className="font-mono text-xs">{scan.scan_id.slice(0, 8)}…</code>
              </span>
              <span className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 border border-slate-700 bg-slate-900/40 text-slate-300">
                {formatDate(scan.created_at)}
              </span>
              {scan.completed_at && (
                <span className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 border border-slate-700 bg-slate-900/40 text-slate-300">
                  Completed: {formatDate(scan.completed_at)}
                </span>
              )}
              <span className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 border border-slate-700 bg-slate-900/40 text-slate-300">
                Duration: {scan.duration_ms ? formatDuration(scan.duration_ms) : "—"}
              </span>
            </div>
          </div>
          <div className="shrink-0 text-right">
            <p className="text-xs uppercase tracking-wider text-slate-500">Scan Status</p>
            <span className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 font-medium ${bandColor(scan.status as string)}`}>
              {scan.status}
            </span>
            {isPartial && (
              <p className="mt-1 text-xs text-slate-500">Some engines unavailable. Missing evidence is not treated as safe.</p>
            )}
          </div>
        </div>
      </section>

      {risk && <RiskAssessmentSection risk={risk} isPartial={isPartial} />}

      <EngineReportsSection engines={engines} />

      {scan.explanation && <ExplanationSection explanation={scan.explanation} />}

      {Object.keys(scan.evidence).length > 0 && <EvidenceSection evidence={scan.evidence} />}
    </article>
  );
}