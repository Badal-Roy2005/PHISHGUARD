"use client";

export function EvidenceSection({ evidence }: { evidence: Record<string, unknown> }) {
  if (Object.keys(evidence).length === 0) return null;
  return (
    <section className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
      <h2 className="text-sm font-medium uppercase tracking-wider text-slate-400">Full Evidence</h2>
      <details className="mt-2 group">
        <summary className="cursor-pointer text-xs text-slate-500 hover:text-slate-300">
          Show raw evidence JSON
        </summary>
        <pre className="mt-2 text-xs text-slate-400 bg-slate-900/40 rounded p-3 overflow-auto max-h-80">
          {JSON.stringify(evidence, null, 2)}
        </pre>
      </details>
    </section>
  );
}