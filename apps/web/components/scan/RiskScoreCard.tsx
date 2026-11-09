"use client";

import type { RiskAssessment } from "@phishguard/contracts";

export function RiskScoreCard({ risk, isPartial }: { risk: RiskAssessment; isPartial: boolean }) {
  const isNull = risk.score === null;

  return (
    <section className="border-2 border-slate-700 bg-slate-900 p-5">
      <h2 className="text-[11px] font-mono font-bold text-cyan-400 uppercase tracking-widest mb-4">
        Risk Assessment
      </h2>
      <div className="grid gap-5 md:grid-cols-3">
        <div className="border-2 border-slate-700/50 p-4 flex flex-col justify-between h-full">
          <div>
            <p className="text-[10px] font-mono text-slate-500 uppercase tracking-widest mb-2">Heuristic Score</p>
            <div className="flex items-center gap-2 mb-2">
              <span className={`text-5xl font-mono font-bold text-slate-100 ${isNull ? "text-slate-500" : "text-cyan-400"}`}>
                {risk.score === null ? "—" : risk.score}
              </span>
              <span className={`inline-flex items-center gap-1.5 rounded-none border-2 px-3 py-1 font-mono font-bold text-[10px] uppercase ${isNull ? "border-slate-700 bg-slate-800 text-slate-400" : "border-cyan-400 bg-cyan-400 text-slate-950"}`}>
                {risk.band}
              </span>
            </div>
          </div>
          <div>
            {isNull && (
              <p className="text-[10px] font-mono text-slate-500 mb-2">
                Coverage below threshold — score suppressed. Missing evidence is not safe.
              </p>
            )}
            <p className="text-[11px] font-mono text-slate-300">{risk.verdict}</p>
            {isPartial && (
              <p className="mt-2 text-[10px] font-mono text-amber-400">
                Partial coverage — some engines unavailable.
              </p>
            )}
          </div>
        </div>
        <div className="border-2 border-slate-700/50 p-4 flex flex-col justify-between h-full">
          <div>
            <p className="text-[10px] font-mono text-slate-500 uppercase tracking-widest mb-2">Threat Likelihood</p>
            <div className="flex items-center gap-2 mb-2">
              <span className="text-3xl font-mono font-bold text-cyan-400">
                {(risk.likelihood.score * 100).toFixed(0)}%
              </span>
              <span className="text-[10px] font-mono text-slate-500">{risk.likelihood.band}</span>
            </div>
          </div>
          <div>
            <p className="mt-1 text-[10px] font-mono text-slate-500/70">
              From intel, URL, brand, redirect evidence — not ML probability.
            </p>
          </div>
        </div>
        <div className="border-2 border-slate-700/50 p-4 flex flex-col justify-between h-full">
          <div>
            <p className="text-[10px] font-mono text-slate-500 uppercase tracking-widest mb-2">Security Posture</p>
            <div className="flex items-center gap-2 mb-2">
              <span className="text-3xl font-mono font-bold text-cyan-400">
                {risk.posture.score === null ? "—" : risk.posture.score}
              </span>
              <span className={`inline-flex items-center gap-1.5 rounded-none border-2 px-3 py-1 font-mono font-bold text-[10px] uppercase border-cyan-400 bg-cyan-400 text-slate-950`}>
                Grade {risk.posture.grade}
              </span>
            </div>
          </div>
          <div>
            <p className="mt-1 text-[10px] font-mono text-slate-500/70">
              Based on TLS and HTTP security configuration.
            </p>
            {risk.posture.penalties.length > 0 && (
              <p className="mt-2 text-[10px] font-mono text-red-400">
                Penalties: {risk.posture.penalties.map((p) => p.id).join(", ")}
              </p>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
