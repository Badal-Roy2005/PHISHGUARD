"use client";

interface ExplanationSectionProps {
  explanation: {
    top_factors: { feature: string; value?: number | string | boolean | null; contribution?: number; direction: string; source: string }[];
    summary: string;
  };
}

export function ExplanationSection({ explanation }: ExplanationSectionProps) {
  return (
    <section className="border-2 border-slate-700/50 bg-slate-800/50 p-5">
      <h2 className="text-[11px] font-mono font-bold text-cyan-400 uppercase tracking-widest mb-4">
        Explanation
      </h2>
      <p className="text-[11px] font-mono text-slate-300 mb-4">{explanation.summary}</p>
      {explanation.top_factors.length > 0 && (
        <>
          <h3 className="text-[10px] font-mono text-slate-500 uppercase tracking-widest mb-3">Top Factors</h3>
          <ul className="space-y-3">
            {explanation.top_factors.map((f, i) => (
              <li key={i} className="border-2 border-slate-700/50 p-3 flex items-start gap-3">
                <span className="shrink-0 inline-flex items-center gap-1 rounded-none border-2 px-2 py-0.5 font-mono font-bold text-[10px] uppercase border-cyan-400 bg-cyan-400 text-slate-950">
                  #{i + 1}
                </span>
                <div className="flex-1">
                  <p className="font-mono text-[10px] text-slate-500">{f.feature}</p>
                  <p className="text-[11px] font-mono text-slate-300">{f.source}</p>
                  <p className="mt-1 text-[10px] font-mono text-slate-500/70">
                    {f.direction === "increases_risk" ? "increases risk" : f.direction === "decreases_risk" ? "decreases risk" : "informational"}
                  </p>
                </div>
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}
