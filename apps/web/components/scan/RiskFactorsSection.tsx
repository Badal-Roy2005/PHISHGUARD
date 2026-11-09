"use client";

import type { RiskAssessment, RiskFactor } from "@phishguard/contracts";

import { severityColor } from "@/lib/ui-utils";

function sortRiskFactors(factors: RiskFactor[]): RiskFactor[] {
  return [...factors].sort((a, b) => (b.contribution ?? 0) - (a.contribution ?? 0));
}

export function RiskFactorsSection({ risk }: { risk: RiskAssessment }) {
  if (!risk.factors || risk.factors.length === 0) return null;
  return (
    <section className="space-y-4">
      <h2 className="text-sm font-medium uppercase tracking-wider text-slate-400">Contributing Factors</h2>
      <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
        <ul className="space-y-3">
          {sortRiskFactors(risk.factors).map((factor, idx) => (
            <li key={`${factor.reason_code}-${idx}`} className="flex items-center gap-2 text-sm">
              <span className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-medium ${severityColor(factor.severity)}`}>
                {factor.severity}
              </span>
              <span className="font-mono text-xs text-slate-300">{factor.reason_code}</span>
              <span className="text-slate-400 flex-1 truncate">{factor.explanation}</span>
              <span className="font-mono text-cyan-400">+{factor.contribution}</span>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}