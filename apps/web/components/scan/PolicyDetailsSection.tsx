"use client";

import type { RiskAssessment } from "@phishguard/contracts";

export function PolicyDetailsSection({ risk }: { risk: RiskAssessment }) {
  const policy = risk.policy;
  return (
    <section className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
      <h2 className="text-sm font-medium uppercase tracking-wider text-slate-400">Scoring Policy</h2>
      <dl className="mt-3 grid gap-2 sm:grid-cols-2 text-sm">
        <dt className="text-slate-500">Version</dt>
        <dd className="font-mono text-slate-300">{policy.version}</dd>
        <dt className="text-slate-500">Calibrated</dt>
        <dd className="font-mono text-slate-300">{policy.calibrated ? "Yes" : "No (heuristic)"}</dd>
        <dt className="text-slate-500">Min coverage for score</dt>
        <dd className="font-mono text-slate-300">{(policy.min_coverage_for_score * 100).toFixed(0)}%</dd>
        <dt className="text-slate-500">Min coverage for low</dt>
        <dd className="font-mono text-slate-300">{(policy.min_coverage_for_low * 100).toFixed(0)}%</dd>
      </dl>
      <div className="mt-4">
        <p className="text-xs text-slate-500">Weights</p>
        <ul className="mt-2 flex flex-wrap gap-2 text-xs">
          {Object.entries(policy.weights).map(([cat, wt]) => (
            <li key={cat} className="inline-flex items-center gap-1 rounded px-2 py-0.5 border border-slate-700 bg-slate-900/40 text-slate-300">
              {cat}: <span className="font-mono text-cyan-400">{wt}</span>
            </li>
          ))}
        </ul>
      </div>
      <ul className="mt-4 space-y-1 text-xs text-slate-500">
        {policy.notes?.map((note, i) => (
          <li key={i} className="flex gap-2">• {note}</li>
        ))}
      </ul>
    </section>
  );
}