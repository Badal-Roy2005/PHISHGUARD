"use client";

import type { RiskAssessment } from "@phishguard/contracts";

import { RiskScoreCard } from "./RiskScoreCard";
import { MLProbabilityCard } from "./MLProbabilityCard";
import { RiskFactorsSection } from "./RiskFactorsSection";
import { PolicyDetailsSection } from "./PolicyDetailsSection";

interface RiskAssessmentSectionProps {
  risk: RiskAssessment;
  isPartial: boolean;
}

export function RiskAssessmentSection({ risk, isPartial }: RiskAssessmentSectionProps) {
  return (
    <section className="space-y-6">
      <RiskScoreCard risk={risk} isPartial={isPartial} />
      <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
        <p className="text-xs uppercase tracking-wider text-slate-500">Evidence Confidence</p>
        <div className="mt-2 grid gap-4 sm:grid-cols-3">
          <div>
            <p className="text-xs text-slate-500">Coverage</p>
            <p className="text-2xl font-mono font-semibold text-cyan-400">{risk.confidence.covered_weight}%</p>
          </div>
          <div>
            <p className="text-xs text-slate-500">Engines OK</p>
            <p className="text-2xl font-mono font-semibold text-cyan-400">{risk.confidence.engines_ok} / {risk.confidence.engines_total}</p>
          </div>
          <div>
            <p className="text-xs text-slate-500">Incomplete</p>
            <p className="text-2xl font-mono font-semibold text-cyan-400">{risk.confidence.incomplete ? "Yes" : "No"}</p>
          </div>
        </div>
        {risk.confidence.missing_evidence && risk.confidence.missing_evidence.length > 0 && (
          <details className="mt-4 group">
            <summary className="flex items-center gap-2 cursor-pointer text-sm text-slate-400 hover:text-slate-200">
              <span className="text-slate-500 group-open:rotate-90 transition-transform">▸</span>
              Missing evidence ({risk.confidence.missing_evidence.length})
            </summary>
            <ul className="mt-2 ml-4 space-y-1 text-xs text-slate-400">
              {risk.confidence.missing_evidence.map((m, i) => (
                <li key={i} className="flex gap-2">{m}</li>
              ))}
            </ul>
          </details>
        )}
      </div>
      <MLProbabilityCard risk={risk} />
      <RiskFactorsSection risk={risk} />
      <PolicyDetailsSection risk={risk} />
    </section>
  );
}