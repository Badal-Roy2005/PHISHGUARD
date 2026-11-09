import { notFound } from "next/navigation";
import Link from "next/link";

import { createClient } from "@/lib/supabase/server";
import { ScanResultDetail } from "@/components/ScanResultDetail";
import type { ScanResult, Engines } from "@phishguard/contracts";

interface ScanPageProps {
  params: Promise<{ id: string }>;
}

export async function generateMetadata({ params }: ScanPageProps) {
  const { id } = await params;
  return { title: `Scan ${id} - PHISHGUARD` };
}

export default async function ScanPage({ params }: ScanPageProps) {
  const { id } = await params;
  const supabase = await createClient();

  const { data: { user } } = await supabase.auth.getUser();

  const { data: scanRow, error } = await supabase
    .from("scans")
    .select("id,url,normalized_url,status,risk_score,risk_band,confidence,policy_version,result,created_at,completed_at,user_id")
    .eq("id", id)
    .maybeSingle();

  if (error || !scanRow) {
    notFound();
  }

  if (scanRow.user_id && (!user || scanRow.user_id !== user.id)) {
    notFound();
  }

  type ScanResultRow = {
  risk?: ScanResult["risk"];
  engines?: Engines;
  explanation?: ScanResult["explanation"];
  evidence?: ScanResult["evidence"];
};

  // Transform database row to ScanResult contract type
  const resultData = scanRow.result as ScanResultRow | null;
  const scan: ScanResult = {
    scan_id: scanRow.id,
    url: scanRow.url,
    normalized_url: scanRow.normalized_url,
    status: scanRow.status,
    created_at: scanRow.created_at,
    completed_at: scanRow.completed_at,
    duration_ms: null,
    risk: resultData?.risk ?? null,
    engines: resultData?.engines ?? {} as Engines,
    explanation: resultData?.explanation ?? null,
    evidence: resultData?.evidence ?? {},
  };

  return (
    <main className="mx-auto max-w-4xl px-6 py-10">
      <header className="flex items-center justify-between gap-4 mb-8">
        <Link href="/" className="text-xs uppercase tracking-[0.2em] text-cyan-400 hover:text-cyan-300">
          PHISHGUARD
        </Link>
        <Link href="/scan" className="text-sm text-slate-400 hover:text-slate-200">
          New scan
        </Link>
      </header>

      <ScanResultDetail scan={scan} />
    </main>
  );
}