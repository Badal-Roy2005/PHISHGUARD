"use client";

import type { EngineReport } from "@phishguard/contracts";

import { severityColor } from "@/lib/ui-utils";

interface EngineDetailProps {
  engine: EngineReport;
}

export function EngineDetail({ engine }: EngineDetailProps) {
  return (
    <details key={engine.engine} className="group mt-4">
      <summary className="flex items-center gap-2 cursor-pointer text-sm font-medium text-slate-300 hover:text-slate-100">
        <span className="text-slate-500 group-open:rotate-90 transition-transform">▸</span>
        {engine.engine} engine details
      </summary>
      <div className="mt-3 space-y-4">
        {engine.findings.length > 0 && (
          <div>
            <p className="text-xs uppercase tracking-wider text-slate-500">Findings</p>
            <ul className="mt-2 space-y-2">
              {engine.findings
                .sort((a, b) => {
                  const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;
                  const sevA = SEVERITY_ORDER.indexOf(a.severity as typeof SEVERITY_ORDER[number]);
                  const sevB = SEVERITY_ORDER.indexOf(b.severity as typeof SEVERITY_ORDER[number]);
                  return sevA - sevB;
                })
                .map((f, i) => (
                  <li key={`${engine.engine}-${i}`} className={`rounded-lg border p-3 ${severityColor(f.severity)}`}>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono text-xs">{f.id}</span>
                      <span className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-medium ${severityColor(f.severity)}`}>
                        {f.severity}
                      </span>
                    </div>
                    <p className="mt-1 text-sm text-slate-200">{f.title}</p>
                    {f.detail && <p className="mt-1 text-xs text-slate-400">{f.detail}</p>}
                    {f.evidence_ref && <p className="mt-1 text-xs text-slate-500">Ref: {f.evidence_ref}</p>}
                  </li>
                ))}
            </ul>
          </div>
        )}
        <details className="group">
          <summary className="cursor-pointer text-xs text-slate-500 hover:text-slate-300">
            Evidence (raw)
          </summary>
          <pre className="mt-2 text-xs text-slate-400 bg-slate-900/40 rounded p-3 overflow-auto max-h-64">
            {JSON.stringify(engine.evidence, null, 2)}
          </pre>
        </details>
      </div>
    </details>
  );
}