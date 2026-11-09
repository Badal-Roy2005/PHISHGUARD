"use client";

import type { Engines } from "@phishguard/contracts";

import { EngineDetail } from "./EngineDetail";

import { formatDuration } from "@/lib/ui-utils";

export function EngineReportsSection({ engines }: { engines: Engines }) {
  const engineEntries = ["ml", "url", "tls", "http", "intel", "community"]
    .filter((e): e is keyof Engines => e in engines)
    .map((e) => engines[e]);

  return (
    <section className="border-2 border-slate-700 bg-slate-900 p-5">
      <h2 className="text-[11px] font-mono font-bold text-cyan-400 uppercase tracking-widest mb-4">
        Engine Reports
      </h2>
      <div className="overflow-x-auto mb-5">
        <table className="w-full text-[10px] font-mono border-collapse border-2 border-slate-700">
          <thead>
            <tr className="border-b border-slate-700/50">
              <th className="text-left py-3 pr-4 text-slate-500 uppercase">Engine</th>
              <th className="text-left py-3 pr-4 text-slate-500 uppercase">Status</th>
              <th className="text-left py-3 pr-4 text-slate-500 uppercase">Findings</th>
              <th className="text-left py-3 pr-4 text-slate-500 uppercase">Duration</th>
              <th className="text-left py-3 pr-4 text-slate-500 uppercase">Source</th>
              <th className="text-left py-3 text-slate-500 uppercase">Error</th>
            </tr>
          </thead>
          <tbody className="text-slate-300">
            {engineEntries.map((engine) => (
              <tr key={engine.engine} className="border-b border-slate-700/10 hover:bg-slate-800/30">
                <td className="py-3 pr-4">{engine.engine}</td>
                <td className="py-3 pr-4">
                  <span className={`inline-flex items-center gap-1.5 rounded-none border-2 px-2 py-0.5 font-mono font-bold text-[10px] uppercase ${
                    engine.status === "ok" ? "border-emerald-500 bg-emerald-900/20 text-emerald-400" :
                    engine.status === "partial" ? "border-amber-500 bg-amber-900/20 text-amber-400" :
                    engine.status === "skipped" || engine.status === "unknown" ? "border-slate-700 bg-slate-800 text-slate-400" :
                    "border-red-500 bg-red-900/20 text-red-400"
                  }`}>
                    {engine.status}
                  </span>
                </td>
                <td className="py-3 pr-4">{engine.findings.length}</td>
                <td className="py-3 pr-4">{formatDuration(engine.duration_ms)}</td>
                <td className="py-3 pr-4 text-slate-500">{engine.source}</td>
                <td className="py-3 text-slate-500/70 max-w-xs truncate">{engine.error ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {engineEntries.map((engine) => (
        <EngineDetail key={engine.engine} engine={engine} />
      ))}
    </section>
  );
}
