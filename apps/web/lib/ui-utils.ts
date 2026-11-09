export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

export type Severity = (typeof SEVERITY_ORDER)[number];

export function severityColor(severity: string): string {
  switch (severity) {
    case "critical": return "text-red-300 border-red-800 bg-red-950/40";
    case "high": return "text-orange-300 border-orange-800 bg-orange-950/40";
    case "medium": return "text-amber-300 border-amber-800 bg-amber-950/40";
    case "low": return "text-emerald-300 border-emerald-800 bg-emerald-950/40";
    default: return "text-slate-400 border-slate-700 bg-slate-900/40";
  }
}

export function bandColor(band: string): string {
  switch (band) {
    case "low": return "text-emerald-400";
    case "guarded": return "text-cyan-400";
    case "suspicious": return "text-amber-400";
    case "high": return "text-orange-400";
    case "critical": return "text-red-400";
    case "insufficient_evidence": return "text-slate-400";
    default: return "text-slate-400";
  }
}

export function engineStatusColor(status: string): string {
  switch (status) {
    case "ok": return "text-emerald-400";
    case "partial": return "text-amber-400";
    case "skipped": return "text-slate-500";
    case "unknown": return "text-slate-500";
    case "error": return "text-red-400";
    default: return "text-slate-500";
  }
}

export function engineStatusLabel(status: string): string {
  switch (status) {
    case "ok": return "OK";
    case "partial": return "Partial";
    case "skipped": return "Skipped";
    case "unknown": return "Unavailable";
    case "error": return "Error";
    default: return status;
  }
}

export function factorStatusColor(status: string): string {
  switch (status) {
    case "applied": return "text-orange-300";
    case "evaluated": return "text-emerald-300";
    case "no_match": return "text-cyan-300";
    case "unavailable": return "text-slate-500";
    case "error": return "text-red-400";
    default: return "text-slate-400";
  }
}

export function directionIcon(direction: string): string {
  switch (direction) {
    case "increases_risk": return "▲";
    case "decreases_risk": return "▼";
    default: return "●";
  }
}

export function formatDate(iso: string): string {
  return new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms.toFixed(1)} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

export function sortFindings<T extends { severity: Severity }>(findings: T[]): T[] {
  return [...findings].sort((a, b) => {
    const sevA = SEVERITY_ORDER.indexOf(a.severity);
    const sevB = SEVERITY_ORDER.indexOf(b.severity);
    return sevA - sevB;
  });
}

export function sortRiskFactors<T extends { contribution?: number }>(factors: T[]): T[] {
  return [...factors].sort((a, b) => (b.contribution ?? 0) - (a.contribution ?? 0));
}

export function postureGradeColor(grade: string): string {
  const g = Number(grade);
  if (g >= 90) return "text-emerald-400";
  if (g >= 80) return "text-cyan-400";
  if (g >= 70) return "text-amber-400";
  if (g >= 60) return "text-orange-400";
  return "text-red-400";
}