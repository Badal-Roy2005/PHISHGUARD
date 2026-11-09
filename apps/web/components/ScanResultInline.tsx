"use client";

import type { ScanResult } from "@phishguard/contracts";

import { RiskAssessmentSection } from "@/components/scan/RiskAssessmentSection";
import { EngineReportsSection } from "@/components/scan/EngineReportsSection";

import { formatDuration, engineStatusColor, engineStatusLabel } from "@/lib/ui-utils";

const ENGINE_ORDER = ["ml", "url", "tls", "http", "intel", "community"] as const;

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
      <div className="mt-8 rounded-lg border border-slate-800 bg-slate-900/40 p-6">
        <p className="text-slate-400">No risk assessment available.</p>
        <button onClick={onNewScan} className="mt-4 text-sm text-cyan-400 hover:text-cyan-300">
          New scan
        </button>
      </div>
    );
  }

  return (
    <div className="mt-8 space-y-8">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Result for <code className="text-cyan-400">{scan.normalized_url}</code></h2>
        <button onClick={onNewScan} className="text-sm text-cyan-400 hover:text-cyan-300">
          New scan
        </button>
      </div>

      <RiskAssessmentSection risk={risk} isPartial={isPartial} />

      <section className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
        <h3 className="text-xs uppercase tracking-wider text-slate-500">Engine Status</h3>
        <div className="mt-3 overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase tracking-wider text-slate-500 border-b border-slate-800">
                <th className="pb-2 pr-4">Engine</th>
                <th className="pb-2 pr-4">Status</th>
                <th className="pb-2 pr-4">Findings</th>
                <th className="pb-2 pr-4">Duration</th>
                <th className="pb-2">Error</th>
              </tr>
            </thead>
            <tbody className="text-slate-300">
              {ENGINE_ORDER
                .filter((e) => engines[e])
                .map((e) => {
                  const engine = engines[e];
                  return (
                    <tr key={e} className="border-t border-slate-800">
                      <td className="py-2 pr-4 font-mono text-cyan-400">{engine.engine}</td>
                      <td className="py-2 pr-4">
                        <span className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-medium ${engineStatusColor(engine.status)}`}>
                          {engineStatusLabel(engine.status)}
                        </span>
                      </td>
                      <td className="py-2 pr-4">{engine.findings.length}</td>
                      <td className="py-2 pr-4 font-mono">{formatDuration(engine.duration_ms)}</td>
                      <td className="py-2 text-xs text-slate-500 max-w-xs truncate">{engine.error ?? "—"}</td>
                    </tr>
                  );
                })}
            </tbody>
          </table>
        </div>
      </section>

      <EngineReportsSection engines={engines} />

      <div className="flex justify-center">
        <button onClick={onNewScan} className="rounded-lg bg-cyan-500 px-4 py-2 font-medium text-slate-950 hover:bg-cyan-400">
          New scan
        </button>
      </div>
    </div>
  );
}