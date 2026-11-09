"use client";

import type { RiskAssessment, RiskFactor } from "@phishguard/contracts";

function sortRiskFactors(factors: RiskFactor[]): RiskFactor[] {
  return [...factors].sort((a, b) => (b.contribution ?? 0) - (a.contribution ?? 0));
}

export function RiskFactorsSection({ risk }: { risk: RiskAssessment }) {
  if (!risk.factors || risk.factors.length === 0) return null;
  return (
    <section className="border-2 border-slate-700 bg-slate-900 p-5">
      <h2 className="text-[11px] font-mono font-bold text-cyan-400 uppercase tracking-widest mb-4">
        Contributing Factors
      </h2>
      <ul className="space-y-3">
        {sortRiskFactors(risk.factors).map((factor, idx) => (
          <li key={`${factor.reason_code}-${idx}`} className="border-2 border-slate-700/50 p-3 flex items-start gap-3">
            <span className={`shrink-0 inline-flex items-center gap-1 rounded-none border-2 px-2 py-0.5 font-mono font-bold text-[10px] uppercase ${
              factor.severity === "critical" ? "border-red-500 bg-red-900/20 text-red-400" :
              factor.severity === "high" ? "border-orange-500 bg-orange-900/20 text-orange-400" :
              factor.severity === "medium" ? "border-amber-500 bg-amber-900/20 text-amber-400" :
              factor.severity === "low" ? "border-emerald-500 bg-emerald-900/20 text-emerald-400" :
              "border-slate-700 bg-slate-800 text-slate-400"
            }`}>
              {factor.severity}
            </span>
            <div className="flex-1">
              <p className="font-mono text-[10px] text-slate-500">{factor.reason_code}</p>
              <p className="text-[11px] font-mono text-slate-300">{factor.explanation}</p>
              <p className="mt-1 text-[10px] font-mono text-slate-500/70">
                {factor.direction === "increases_risk" ? "increases risk" : factor.direction === "decreases_risk" ? "decreases risk" : "informational"}
                {factor.contribution && factor.contribution !== 0 ? ` &bull; {factor.contribution > 0 ? "+" : ""}${factor.contribution}` : ""}
              </p>
            </div>
          </li>
        ))}
      </ul>
    </section>
  );
}
