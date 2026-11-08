import {
  CONTRACT_VERSION,
  ENGINE_NAMES,
  LABEL_MAP,
  SCAN_STATUSES,
  SERVICE_VERSION,
} from "@phishguard/contracts";

const MILESTONES = [
  { id: "M0", label: "Foundation", state: "done" },
  { id: "M1", label: "Contracts", state: "done" },
  { id: "M2", label: "ML training", state: "next" },
  { id: "M3", label: "URL engine", state: "queued" },
  { id: "M4", label: "Scanner + SSRF", state: "queued" },
  { id: "M5", label: "Threat intel", state: "queued" },
  { id: "M6", label: "TLS / HTTP", state: "queued" },
  { id: "M7", label: "Risk scoring", state: "queued" },
] as const;

export default function Home() {
  return (
    <main className="mx-auto max-w-3xl px-6 py-16">
      <p className="text-xs uppercase tracking-[0.2em] text-cyan-400">HackMatrix 2026</p>
      <h1 className="mt-2 text-4xl font-semibold tracking-tight">PHISHGUARD</h1>
      <p className="mt-2 text-sm text-slate-400">
        Trust the link. Verify the destination. Foundation build — M0/M1 only, no
        scanning yet.
      </p>

      <section className="mt-10 grid gap-3 sm:grid-cols-3">
        <Card label="Service" value={SERVICE_VERSION} />
        <Card label="Contract" value={CONTRACT_VERSION} />
        <Card label="Scan states" value={SCAN_STATUSES.length.toString()} />
      </section>

      <section className="mt-10">
        <h2 className="text-sm font-medium uppercase tracking-wider text-slate-400">
          Milestones
        </h2>
        <ul className="mt-3 divide-y divide-slate-800 rounded-lg border border-slate-800">
          {MILESTONES.map((m) => (
            <li key={m.id} className="flex items-center justify-between px-4 py-2 text-sm">
              <span>
                <span className="text-slate-500">{m.id}</span>{" "}
                <span className="text-slate-200">{m.label}</span>
              </span>
              <span className={m.state === "done" ? "text-emerald-400" : "text-slate-500"}>
                {m.state}
              </span>
            </li>
          ))}
        </ul>
      </section>

      <section className="mt-10 text-xs text-slate-500">
        <p>
          Engines: {ENGINE_NAMES.join(", ")}. Labels: 0 = {LABEL_MAP["0"]}, 1 ={" "}
          {LABEL_MAP["1"]}.
        </p>
      </section>
    </main>
  );
}

function Card({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/40 px-4 py-3">
      <p className="text-xs uppercase tracking-wider text-slate-500">{label}</p>
      <p className="mt-1 font-mono text-sm text-slate-200">{value}</p>
    </div>
  );
}
