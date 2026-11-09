"use client";

import type { RiskAssessment } from "@phishguard/contracts";

import { bandColor, postureGradeColor } from "@/lib/ui-utils";

interface RiskScoreCardProps {
  risk: RiskAssessment;
  isPartial: boolean;
}

export function RiskScoreCard({ risk, isPartial }: RiskScoreCardProps) {
  return (
    <section className="rounded-lg border border-slate-800 bg-slate-900/40 p-6">
      <h2 className="text-sm font-medium uppercase tracking-wider text-slate-400">Risk Assessment</h2>
      <div className="mt-4 grid gap-6 md:grid-cols-4">
        <div className="md:col-span-2">
          <p className="text-xs uppercase tracking-wider text-slate-500">Heuristic Risk Score</p>
          <div className="mt-2 flex items-baseline gap-4">
            <span className={`text-5xl font-mono font-semibold ${risk.score === null ? "text-slate-400" : bandColor(risk.band)}`}>
              {risk.score === null ? "—" : risk.score}
            </span>
            <span className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1 font-semibold text-lg ${bandColor(risk.band)}`}>
              {risk.band}
            </span>
          </div>
          {risk.score === null && (
            <p className="mt-2 text-sm text-slate-400">
              {risk.confidence.covered_weight < 50
                ? "Insufficient evidence for a reliable score. Coverage below 50%."
                : "Score suppressed: evidence coverage below 75% threshold for 'low' band."}
            </p>
          )}
          <p className="mt-3 text-sm text-slate-300">{risk.verdict}</p>
          {isPartial && (
            <p className="mt-2 text-xs text-amber-400">Some engines unavailable. Missing evidence is not treated as safe.</p>
          )}
        </div>
        <div className="md:col-span-2 space-y-4">
          <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
            <p className="text-xs uppercase tracking-wider text-slate-500">Threat Likelihood</p>
            <div className="mt-2 flex items-baseline gap-4">
              <span className="text-3xl font-mono font-semibold text-cyan-400">
                {(risk.likelihood.score * 100).toFixed(0)}%
              </span>
              <span className="text-sm text-slate-400">{risk.likelihood.band}</span>
            </div>
            <p className="mt-1 text-xs text-slate-500">
              From intel, URL, brand, and redirect evidence. Not ML probability.
            </p>
          </div>
          <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
            <p className="text-xs uppercase tracking-wider text-slate-500">Security Posture</p>
            <div className="mt-2 flex items-baseline gap-4">
              <span className="text-3xl font-mono font-semibold text-cyan-400">
                {risk.posture.score === null ? "—" : risk.posture.score}
              </span>
              <span className={`text-sm font-semibold ${postureGradeColor(risk.posture.grade)}`}>
                Grade {risk.posture.grade}
              </span>
            </div>
            <p className="mt-1 text-xs text-slate-500">
              Based on TLS and HTTP security configuration.
              {risk.posture.penalties.length > 0 && (
                <span className="ml-2">Penalties: {risk.posture.penalties.map((p) => p.id).join(", ")}</span>
              )}
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}