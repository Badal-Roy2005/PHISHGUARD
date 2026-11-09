export const COLORS = {
  bg: "bg-slate-950",
  surface: "bg-slate-900",
  surfaceLift: "bg-slate-800",
  border: "border-slate-700",
  borderLight: "border-slate-600",
  text: "text-slate-100",
  textMuted: "text-slate-400",
  textDim: "text-slate-500",
  primary: "text-cyan-400",
  primaryBg: "bg-cyan-400",
  primaryText: "text-slate-950",
  danger: "text-red-400",
  dangerBg: "bg-red-400",
  dangerText: "text-slate-950",
  warning: "text-amber-400",
  warningBg: "bg-amber-400",
  warningText: "text-slate-950",
  success: "text-emerald-400",
  successBg: "bg-emerald-400",
  successText: "text-slate-950",
} as const;

export function bandColorClass(band: string): string {
  switch (band) {
    case "low": return "text-emerald-400 border-emerald-500 bg-emerald-500 text-slate-950";
    case "guarded": return "text-amber-400 border-amber-500 bg-amber-500 text-slate-950";
    case "suspicious": return "text-orange-400 border-orange-500 bg-orange-500 text-slate-950";
    case "high": return "text-red-400 border-red-500 bg-red-500 text-slate-950";
    case "critical": return "text-red-400 border-red-500 bg-red-500 text-slate-950";
    case "insufficient_evidence": return "text-slate-400 border-slate-600 bg-slate-900";
    default: return "text-slate-400 border-slate-600 bg-slate-900";
  }
}

export function severityColorClass(severity: string): string {
  switch (severity) {
    case "critical": return "text-red-400 border-red-500 bg-red-500 text-slate-950";
    case "high": return "text-orange-400 border-orange-500 bg-orange-500 text-slate-950";
    case "medium": return "text-amber-400 border-amber-500 bg-amber-500 text-slate-950";
    case "low": return "text-emerald-400 border-emerald-500 bg-emerald-500 text-slate-950";
    case "info": return "text-cyan-400 border-cyan-500 bg-cyan-500 text-slate-950";
    default: return "text-slate-400 border-slate-600 bg-slate-900";
  }
}

export function engineStatusColorClass(status: string): string {
  switch (status) {
    case "ok": return "text-emerald-400 border-emerald-500 bg-emerald-500 text-slate-950";
    case "partial": return "text-amber-400 border-amber-500 bg-amber-500 text-slate-950";
    case "skipped": return "text-slate-400 border-slate-600 bg-slate-900";
    case "unknown": return "text-slate-400 border-slate-600 bg-slate-900";
    case "error": return "text-red-400 border-red-500 bg-red-500 text-slate-950";
    default: return "text-slate-400 border-slate-600 bg-slate-900";
  }
}

export function factorDirectionColorClass(direction: string): string {
  switch (direction) {
    case "increases_risk": return "text-red-400 border-red-500 bg-red-500 text-slate-950";
    case "decreases_risk": return "text-emerald-400 border-emerald-500 bg-emerald-500 text-slate-950";
    default: return "text-slate-400 border-slate-600 bg-slate-900";
  }
}

export function postureGradeColorClass(grade: string): string {
  const g = Number(grade);
  if (g >= 90) return "text-emerald-400 border-emerald-500 bg-emerald-500 text-slate-950";
  if (g >= 80) return "text-cyan-400 border-cyan-500 bg-cyan-500 text-slate-950";
  if (g >= 70) return "text-amber-400 border-amber-500 bg-amber-500 text-slate-950";
  if (g >= 60) return "text-orange-400 border-orange-500 bg-orange-500 text-slate-950";
  return "text-red-400 border-red-500 bg-red-500 text-slate-950";
}
