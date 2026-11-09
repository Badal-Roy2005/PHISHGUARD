"use client";

import type { RiskAssessment } from "@phishguard/contracts";

export function PolicyDetailsSection({ risk }: { risk: RiskAssessment }) {
  const policy = risk.policy;
  return (
    <section className="border-2 border-slate-700/50 bg-slate-800/50 p-5">
      <h2 className="text-[11px] font-mono font-bold text-cyan-400 uppercase tracking-widest mb-4">
        Scoring Policy
      </h2>
      <dl className="grid gap-3 sm:grid-cols-2 text-[10px] font-mono text-slate-300 mb-5">
        <div className="border-b border-slate-700/30 pb-2">
          <dt className="text-slate-500 uppercase">Version</dt>
          <dd className="text-slate-300">{policy.version}</dd>
        </div>
        <div className="border-b border-slate-700/30 pb-2">
          <dt className="text-slate-500 uppercase">Calibrated</dt>
          <dd className="text-slate-300">{policy.calibrated ? "Yes" : "No (heuristic)"}</dd>
        </div>
        <div className="border-b border-slate-700/30 pb-2">
          <dt className="text-slate-500 uppercase">Min coverage for score</dt>
          <dd className="text-slate-300">{policy.min_coverage_for_score * 100}%</dd>
        </div>
        <div className="border-b border-slate-700/30 pb-2">
          <dt className="text-slate-500 uppercase">Min coverage for low</dt>
          <dd className="text-slate-300">{policy.min_coverage_for_low * 100}%</dd>
        </div>
      </dl>
      <div className="border-2 border-slate-700/50 p-3 mb-5">
        <h3 className="text-[10px] font-mono text-slate-500 uppercase tracking-widest mb-2">Weights</h3>
        <ul className="flex flex-wrap gap-2 text-[10px] font-mono text-slate-300">
          {Object.entries(policy.weights).map(([cat, wt]) => (
            <li key={cat} className="border-2 border-slate-700 px-2 py-0.5">
              {cat}: <span className="text-cyan-400">{wt}</span>
            </li>
          ))}
        </ul>
      </div>
      <ul className="space-y-2 text-[10px] font-mono text-slate-500">
        {policy.notes?.map((note, i) => (
          <li key={i} className="flex gap-1">{note}</li>
        ))}
      </ul>
    </section>
  );
}
