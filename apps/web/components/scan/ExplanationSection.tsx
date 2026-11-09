"use client";

interface ExplanationSectionProps {
  explanation: {
    top_factors: { feature: string; value?: number | string | boolean | null; contribution?: number; direction: string; source: string }[];
    summary: string;
  };
}

export function ExplanationSection({ explanation }: ExplanationSectionProps) {
  return (
    <section className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
      <h2 className="text-sm font-medium uppercase tracking-wider text-slate-400">Explanation</h2>
      <p className="mt-2 text-sm text-slate-300">{explanation.summary}</p>
      {explanation.top_factors.length > 0 && (
        <ul className="mt-4 space-y-2">
          {explanation.top_factors.map((f, i) => (
            <li key={i} className="flex items-center gap-3 text-sm">
              <span className="shrink-0 w-6 h-6 flex items-center justify-center rounded bg-slate-800 text-xs font-mono text-cyan-400">
                {i + 1}
              </span>
              <span className="font-mono text-xs text-slate-400">{f.feature}</span>
              <span className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-medium ${
                f.direction === "increases_risk" ? "text-orange-300 border-orange-800 bg-orange-950/40" :
                f.direction === "decreases_risk" ? "text-emerald-300 border-emerald-800 bg-emerald-950/40" :
                "text-slate-400 border-slate-700 bg-slate-900/40"
              }`}>
                {f.contribution && f.contribution > 0 ? `+${f.contribution}` : "0"}
              </span>
              <span className="text-slate-500">{f.source}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}