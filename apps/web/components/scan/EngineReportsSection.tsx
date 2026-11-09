"use client";

import type { Engines } from "@phishguard/contracts";

import { EngineDetail } from "./EngineDetail";

import { engineStatusColor, engineStatusLabel, formatDuration } from "@/lib/ui-utils";

export function EngineReportsSection({ engines }: { engines: Engines }) {
  const engineEntries = ["ml", "url", "tls", "http", "intel", "community"]
    .filter((e): e is "ml" | "url" | "tls" | "http" | "intel" | "community" => e in engines)
    .map((e) => engines[e]);

  return (
    <section className="space-y-4">
      <h2 className="text-sm font-medium uppercase tracking-wider text-slate-400">Engine Reports</h2>
      <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase tracking-wider text-slate-500 border-b border-slate-800">
                <th className="pb-2 pr-4">Engine</th>
                <th className="pb-2 pr-4">Status</th>
                <th className="pb-2 pr-4">Findings</th>
                <th className="pb-2 pr-4">Duration</th>
                <th className="pb-2 pr-4">Source</th>
                <th className="pb-2">Error</th>
              </tr>
            </thead>
            <tbody className="text-slate-300">
              {engineEntries.map((engine) => (
                <tr key={engine.engine} className="border-t border-slate-800">
                  <td className="py-2 pr-4 font-mono text-cyan-400">{engine.engine}</td>
                  <td className="py-2 pr-4">
                    <span className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-medium ${engineStatusColor(engine.status)}`}>
                      {engineStatusLabel(engine.status)}
                    </span>
                  </td>
                  <td className="py-2 pr-4">{engine.findings.length}</td>
                  <td className="py-2 pr-4 font-mono">{formatDuration(engine.duration_ms)}</td>
                  <td className="py-2 pr-4 text-xs text-slate-500">{engine.source}</td>
                  <td className="py-2 text-xs text-slate-500 max-w-xs truncate">{engine.error ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {engineEntries.map((engine) => (
          <EngineDetail key={engine.engine} engine={engine} />
        ))}
      </div>
    </section>
  );
}