"use client";

export function EvidenceSection({ evidence }: { evidence: Record<string, unknown> }) {
  if (Object.keys(evidence).length === 0) return null;
  return (
    <section className="border-2 border-slate-700/50 bg-slate-800/50 p-5">
      <h2 className="text-[11px] font-mono font-bold text-cyan-400 uppercase tracking-widest mb-4">
        Full Evidence
      </h2>
      <details className="group">
        <summary className="cursor-pointer text-[10px] font-mono text-slate-500 hover:text-cyan-400 uppercase tracking-widest">
          Show raw evidence JSON
        </summary>
        <pre className="mt-2 text-[10px] font-mono text-slate-500/70 border-2 border-slate-700/50 bg-slate-950 p-3 overflow-x-auto max-h-80">
          {JSON.stringify(evidence, null, 2)}
        </pre>
      </details>
    </section>
  );
}
