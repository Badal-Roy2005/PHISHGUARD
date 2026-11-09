import { ScanForm } from "@/components/ScanForm";

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
  { id: "M2", label: "ML training", state: "done" },
  { id: "M3", label: "URL engine", state: "done" },
  { id: "M4", label: "Scanner + SSRF", state: "done" },
  { id: "M5", label: "Threat intel", state: "done" },
  { id: "M6", label: "TLS / HTTP", state: "done" },
  { id: "M7", label: "Risk scoring", state: "done" },
  { id: "M8", label: "Persistence + auth", state: "local" },
] as const;

export default function Home() {
  return (
    <div className="min-h-screen flex flex-col bg-slate-950 text-slate-100">
      <section className="px-4 sm:px-6 py-16 sm:py-24 border-b-2 border-slate-800">
        <div className="mx-auto max-w-3xl text-center">
          <p className="text-[10px] font-mono font-bold text-cyan-400 uppercase tracking-widest">
            Phishing Defense Platform
          </p>
          <h1 className="mt-4 text-5xl font-mono font-bold text-slate-100 tracking-tighter sm:text-6xl">
            Verify every link.
          </h1>
          <p className="mt-6 text-lg text-slate-400 max-w-xl mx-auto leading-relaxed font-mono">
            Analyze any URL for phishing risk. URL structure checks, live fetch inspection,
            threat-intelligence lookups, TLS/HTTP assessment, and deterministic risk scoring
            — without executing the target site's code.
          </p>
          <ScanForm variant="hero" className="mt-12 mx-auto max-w-5xl" />
        </div>
      </section>

      <section className="px-4 sm:px-6 py-16 border-b-2 border-slate-800">
        <div className="mx-auto max-w-7xl">
          <div className="text-center mb-14">
            <h2 className="text-2xl font-mono font-bold text-slate-100 sm:text-3xl">
              How PHISHGUARD works
            </h2>
            <p className="mt-3 text-slate-400 font-mono">
              Multi-engine detection with explainable risk scoring.
            </p>
          </div>

          <ol className="grid gap-4 sm:grid-cols-3">
            {[
              {
                num: "1",
                title: "URL analysis",
                desc: "Lexical and structural checks for obfuscation and abnormal patterns.",
              },
              {
                num: "2",
                title: "Live inspection",
                desc: "DNS-pinned fetch with TLS capture and redirect validation — SSRF-protected.",
              },
              {
                num: "3",
                title: "Threat intel",
                desc: "Google Safe Browsing and URLhaus lookups against known indicators.",
              },
              {
                num: "4",
                title: "TLS / HTTP",
                desc: "Certificate details, cipher suites, missing security headers.",
              },
              {
                num: "5",
                title: "Risk scoring",
                desc: "Policy-versioned aggregation — incomplete evidence is never safe.",
              },
            ].map((step) => (
              <li key={step.title} className="border-2 border-slate-800 bg-slate-900/50 p-4">
                <div className="flex items-center gap-2 mb-3">
                  <span className="border-2 border-cyan-400 bg-cyan-400 text-slate-950 font-mono font-bold text-[10px] uppercase px-2 py-0.5">
                    {step.num}
                  </span>
                  <h3 className="font-mono font-bold text-slate-100">{step.title}</h3>
                </div>
                <p className="text-[11px] font-mono text-slate-400 leading-relaxed">
                  {step.desc}
                </p>
              </li>
            ))}
          </ol>
        </div>
      </section>

      <section className="px-4 sm:px-6 py-20">
        <div className="mx-auto max-w-7xl">
          <div className="flex flex-col lg:flex-row gap-8 items-start">
            <div className="lg:w-1/3 flex-none">
              <h2 className="text-2xl font-mono font-bold text-slate-100">Service status</h2>
              <p className="mt-3 text-slate-400 font-mono leading-relaxed">
                All M0–M7 engines verified locally. M8 persistence and authentication
                are implemented locally. Scan results are policy-versioned and
                coverage-aware.
              </p>
            </div>
            <div className="flex-1 grid grid-cols-3 gap-4 mt-8 lg:mt-0">
              <StatCard label="Service" value={SERVICE_VERSION} />
              <StatCard label="Contract" value={CONTRACT_VERSION} />
              <StatCard label="Scan states" value={SCAN_STATUSES.length.toString()} />
            </div>
          </div>

          <section className="mt-16 border-2 border-slate-800 bg-slate-900/30 p-5">
            <h2 className="text-[11px] font-mono font-bold text-cyan-400 uppercase tracking-widest mb-4">
              Milestones
            </h2>
            <ul className="divide-y divide-slate-800/50">
              {MILESTONES.map((m) => (
                <li key={m.id} className="flex items-center justify-between py-4 text-[11px] font-mono">
                  <div className="flex items-center gap-3">
                    <span className="text-slate-500">{m.id}</span>
                    <span className="text-slate-200">{m.label}</span>
                  </div>
                  <span
                    className={`inline-flex items-center gap-1 rounded-none border-2 px-2.5 py-0.5 text-[10px] ${
                      m.state === "done"
                        ? "border-emerald-500 bg-emerald-900/20 text-emerald-400"
                        : m.state === "local"
                          ? "border-amber-500 bg-amber-900/20 text-amber-400"
                          : "border-slate-700 bg-slate-800 text-slate-400"
                    }`}
                  >
                    {m.state}
                  </span>
                </li>
              ))}
            </ul>
          </section>

          <section className="mt-16 text-[10px] font-mono text-slate-500">
            <p>
              Engines: {ENGINE_NAMES.join(", ")}. Labels: 0 ={" "}
              {LABEL_MAP["0"]}, 1 = {LABEL_MAP["1"]}.
            </p>
          </section>
        </div>
      </section>
    </div>
  );
}

function StatCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="border-2 border-slate-800 bg-slate-900/30 p-3">
      <p className="text-[10px] font-mono text-slate-500 uppercase tracking-widest mb-1">
        {label}
      </p>
      <p className="font-mono font-bold text-cyan-400">{value}</p>
    </div>
  );
}
