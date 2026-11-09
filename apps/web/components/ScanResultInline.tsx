"use client";

import type { ScanResult } from "@phishguard/contracts";

import { RiskAssessmentSection } from "@/components/scan/RiskAssessmentSection";
import { EngineReportsSection } from "@/components/scan/EngineReportsSection";
import { EvidenceSection } from "@/components/scan/EvidenceSection";
import { ExplanationSection } from "@/components/scan/ExplanationSection";

import { formatDuration } from "@/lib/ui-utils";

interface ScanResultInlineProps {
  scan: ScanResult;
  onNewScan: () => void;
}

export function ScanResultInline({ scan, onNewScan }: ScanResultInlineProps) {
  const risk = scan.risk;
  const engines = scan.engines;
  const isPartial = scan.status === "partial";

  if (!risk) {
    return (
      <div className="mt-6 border-2 border-slate-700 bg-slate-900 p-5">
        <h2 className="text-lg font-mono font-bold text-cyan-400 mb-3">No assessment</h2>
        <p className="text-slate-400 font-mono text-sm">No risk assessment available for this scan.</p>
        <button
          onClick={onNewScan}
          className="mt-4 border-2 border-cyan-400 bg-cyan-400 text-slate-950 font-mono font-bold text-xs px-3 py-1.5 hover:bg-cyan-300 transition-colors"
        >
          New scan
        </button>
      </div>
    );
  }

  return (
    <div className="mt-6 space-y-6">
      <div className="border-2 border-slate-700 bg-slate-900 p-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-700 pb-3 mb-4">
          <div className="flex-1">
            <h2 className="text-lg font-mono font-bold text-cyan-400">Target</h2>
            <p className="text-slate-300 font-mono text-sm break-all">{scan.normalized_url}</p>
          </div>
          <div className="text-right hidden md:block">
            <p className="text-[10px] font-mono text-slate-500 uppercase tracking-widest">Scan ID</p>
            <p className="text-cyan-300 font-mono text-xs break-all">{scan.scan_id}</p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3 mb-4">
          <span className={`inline-flex items-center gap-1.5 rounded-none border-2 px-3 py-1 font-mono font-bold text-[10px] uppercase ${isPartial ? "border-amber-500 bg-amber-900/20 text-amber-400" : "border-emerald-500 bg-emerald-900/20 text-emerald-400"}`}>
            {scan.status.toUpperCase()}
          </span>
          <span className="text-slate-300 font-mono text-sm">
            Completed in {scan.duration_ms ? formatDuration(scan.duration_ms) : "—"}
          </span>
        </div>
      </div>

      <RiskAssessmentSection risk={risk} isPartial={isPartial} />
      <EngineReportsSection engines={engines} />
      <ExplanationSection explanation={scan.explanation ?? { top_factors: [], summary: "" }} />
      <EvidenceSection evidence={scan.evidence} />

      <div className="border-2 border-slate-700 bg-slate-900 p-5 text-center">
        <button
          onClick={onNewScan}
          className="border-2 border-cyan-400 bg-cyan-400 text-slate-950 font-mono font-bold text-xs px-4 py-2 hover:bg-cyan-300 transition-colors"
        >
          New scan
        </button>
      </div>
    </div>
  );
}
