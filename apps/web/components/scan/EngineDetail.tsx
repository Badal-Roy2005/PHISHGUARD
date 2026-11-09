"use client";

import type { EngineReport } from "@phishguard/contracts";

interface EngineDetailProps {
  engine: EngineReport;
}

export function EngineDetail({ engine }: EngineDetailProps) {
  return (
    <details key={engine.engine} className="mt-5 border-2 border-slate-700/50 bg-slate-800/50">
      <summary className="cursor-pointer border-b border-slate-700/30 p-3 font-mono font-bold text-cyan-400">
        {engine.engine} engine details
      </summary>
      <div className="p-4 space-y-4">
        {engine.findings.length > 0 && (
          <>
            <h3 className="text-[10px] font-mono text-slate-500 uppercase tracking-widest">Findings</h3>
            <ul className="space-y-3">
              {engine.findings.map((f, i) => (
                <li key={`${engine.engine}-${i}`} className="border-2 border-slate-700/50 p-3">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="font-mono text-[10px] text-slate-400">{f.id}</span>
                    <span className={`rounded-none border-2 px-1.5 py-0.5 font-mono font-bold text-[10px] uppercase ${
                      f.severity === "critical" ? "border-red-500 bg-red-900/20 text-red-400" :
                      f.severity === "high" ? "border-orange-500 bg-orange-900/20 text-orange-400" :
                      f.severity === "medium" ? "border-amber-500 bg-amber-900/20 text-amber-400" :
                      f.severity === "low" ? "border-emerald-500 bg-emerald-900/20 text-emerald-400" :
                      f.severity === "info" ? "border-cyan-500 bg-cyan-900/20 text-cyan-400" :
                      "border-slate-700 bg-slate-800 text-slate-400"
                    }`}>
                      {f.severity}
                    </span>
                  </div>
                  <p className="text-[11px] font-mono text-slate-300">{f.title}</p>
                  {f.detail && <p className="mt-1 text-[10px] font-mono text-slate-500/70">{f.detail}</p>}
                  {f.evidence_ref && (
                    <p className="mt-1 text-[10px] font-mono text-slate-500/50">Ref: {f.evidence_ref}</p>
                  )}
                </li>
              ))}
            </ul>
          </>
        )}
        <details className="group">
          <summary className="cursor-pointer text-[10px] font-mono text-slate-500 hover:text-cyan-400 uppercase tracking-widest">
            Evidence (raw)
          </summary>
          <pre className="mt-2 text-[10px] font-mono text-slate-500/70 border-2 border-slate-700/50 bg-slate-950 p-3 overflow-x-auto max-h-64">
            {JSON.stringify(engine.evidence, null, 2)}
          </pre>
        </details>
      </div>
    </details>
  );
}
