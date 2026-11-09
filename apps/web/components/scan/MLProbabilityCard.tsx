"use client";

import type { RiskAssessment } from "@phishguard/contracts";

export function MLProbabilityCard({ risk }: { risk: RiskAssessment }) {
  if (!risk.model_probability) return null;
  return (
    <section className="border-2 border-slate-700 bg-slate-900 p-5">
      <h2 className="text-[11px] font-mono font-bold text-cyan-400 uppercase tracking-widest mb-4">
        ML Phishing Probability
      </h2>
      <p className="text-[10px] font-mono text-slate-500 mb-3">
        Not included in risk score above.
      </p>
      <div className="flex items-baseline gap-2">
        <span className="text-4xl font-mono font-bold text-cyan-400">
          {(risk.model_probability.probability_phishing * 100).toFixed(1)}%
        </span>
        <span className={`inline-flex items-center gap-1.5 rounded-none border-2 px-3 py-1 font-mono font-bold text-[10px] uppercase border-cyan-400 bg-cyan-400 text-slate-950`}>
          {risk.model_probability.label}
        </span>
      </div>
      <p className="mt-1 text-[10px] font-mono text-slate-500/70">
        Model: {risk.model_probability.model_version ?? "unknown"} &bull; {risk.model_probability.status} &bull; {risk.model_probability.calibrated ? "Calibrated" : "Uncalibrated"}
      </p>
    </section>
  );
}
