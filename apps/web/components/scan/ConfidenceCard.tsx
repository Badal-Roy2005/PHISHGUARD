"use client";

import type { RiskAssessment } from "@phishguard/contracts";

export function ConfidenceCard({ risk }: { risk: RiskAssessment }) {
  return (
    <section className="border-2 border-slate-700 bg-slate-900 p-5">
      <h2 className="text-[11px] font-mono font-bold text-cyan-400 uppercase tracking-widest mb-4">
        Evidence Confidence
      </h2>
      <div className="grid gap-4 md:grid-cols-3">
        <div className="border-2 border-slate-700/50 p-3 text-center">
          <p className="text-[10px] font-mono text-slate-500 uppercase mb-1">Coverage</p>
          <p className="text-2xl font-mono font-bold text-cyan-400">{risk.confidence.covered_weight}%</p>
        </div>
        <div className="border-2 border-slate-700/50 p-3 text-center">
          <p className="text-[10px] font-mono text-slate-500 uppercase mb-1">Engines OK</p>
          <p className="text-2xl font-mono font-bold text-cyan-400">
            {risk.confidence.engines_ok} / {risk.confidence.engines_total}
          </p>
        </div>
        <div className="border-2 border-slate-700/50 p-3 text-center">
          <p className="text-[10px] font-mono text-slate-500 uppercase mb-1">Incomplete</p>
          <p className={`text-2xl font-mono font-bold ${risk.confidence.incomplete ? "text-amber-400" : "text-emerald-400"}`}>
            {risk.confidence.incomplete ? "YES" : "NO"}
          </p>
        </div>
      </div>
      {risk.confidence.missing_evidence && risk.confidence.missing_evidence.length > 0 && (
        <details className="mt-4 border-t border-slate-700/30 pt-3 group">
          <summary className="cursor-pointer text-[10px] font-mono text-slate-500 hover:text-cyan-400 uppercase tracking-widest">
            Missing evidence ({risk.confidence.missing_evidence.length})
          </summary>
          <ul className="mt-2 space-y-1 text-xs font-mono text-slate-500">
            {risk.confidence.missing_evidence.map((m, i) => (
              <li key={i} className="flex gap-1">{m}</li>
            ))}
          </ul>
        </details>
      )}
    </section>
  );
}
