"use client";

import type { RiskAssessment } from "@phishguard/contracts";

export function MLProbabilityCard({ risk }: { risk: RiskAssessment }) {
  if (!risk.model_probability) return null;
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
      <div className="flex items-center justify-between">
        <p className="text-xs uppercase tracking-wider text-slate-500">ML Phishing Probability</p>
        <span className="text-xs text-slate-500">Not included in risk score above</span>
      </div>
      <div className="mt-2 flex items-baseline gap-4">
        <span className="text-4xl font-mono font-semibold text-cyan-400">
          {(risk.model_probability!.probability_phishing * 100).toFixed(1)}%
        </span>
        <span className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1 text-sm font-medium ${
          risk.model_probability!.label === "phishing" ? "text-red-400 border-red-800 bg-red-950/40" :
          risk.model_probability!.label === "legitimate" ? "text-emerald-400 border-emerald-800 bg-emerald-950/40" :
          "text-slate-400 border-slate-700 bg-slate-900/40"
        }`}>
          {risk.model_probability!.label}
        </span>
      </div>
      <p className="mt-1 text-xs text-slate-500">
        Model: {risk.model_probability!.model_version ?? "unknown"} · Status: {risk.model_probability!.status} · {risk.model_probability!.calibrated ? "Calibrated" : "Uncalibrated"}
      </p>
    </div>
  );
}