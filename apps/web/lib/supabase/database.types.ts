// Generated-type shape for the M8 public schema.
// Regenerate after linking a project:
//   pnpm --filter @phishguard/web db:types
// The checked-in version is hand-maintained until a project is linked because
// this repository has no Supabase CLI/project configured.

export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[];

export type AppRole = "user" | "moderator" | "admin";
export type ScanStatus = "queued" | "running" | "complete" | "partial" | "failed";
export type RiskBand =
  | "low"
  | "guarded"
  | "suspicious"
  | "high"
  | "critical"
  | "insufficient_evidence";

export interface Database {
  public: {
    Tables: {
      profiles: {
        Row: {
          id: string;
          email: string | null;
          display_name: string | null;
          role: AppRole;
          created_at: string;
          updated_at: string;
        };
        Insert: {
          id: string;
          email?: string | null;
          display_name?: string | null;
          role?: AppRole;
          created_at?: string;
          updated_at?: string;
        };
        Update: {
          display_name?: string | null;
        };
        Relationships: [];
      };
      scans: {
        Row: {
          id: string;
          user_id: string | null;
          url: string;
          normalized_url: string;
          url_hash: string;
          status: ScanStatus;
          risk_score: number | null;
          risk_band: RiskBand | null;
          confidence: number | null;
          policy_version: string | null;
          result: Json | null;
          created_at: string;
          completed_at: string | null;
          expires_at: string | null;
          inserted_at: string;
        };
        Insert: {
          id?: string;
          user_id?: string | null;
          url: string;
          normalized_url: string;
          url_hash: string;
          status: ScanStatus;
          risk_score?: number | null;
          risk_band?: RiskBand | null;
          confidence?: number | null;
          policy_version?: string | null;
          result?: Json | null;
          created_at?: string;
          completed_at?: string | null;
          expires_at?: string | null;
          inserted_at?: string;
        };
        Update: {
          risk_score?: number | null;
          risk_band?: RiskBand | null;
          confidence?: number | null;
          policy_version?: string | null;
          result?: Json | null;
          completed_at?: string | null;
          expires_at?: string | null;
        };
        Relationships: [
          {
            foreignKeyName: "scans_user_id_fkey";
            columns: ["user_id"];
            isOneToOne: false;
            referencedRelation: "profiles";
            referencedColumns: ["id"];
          },
        ];
      };
    };
    Views: {
      [_ in never]: never;
    };
    Functions: {
      [_ in never]: never;
    };
    Enums: {
      app_role: AppRole;
      scan_status: ScanStatus;
      risk_band: RiskBand;
    };
    CompositeTypes: {
      [_ in never]: never;
    };
  };
}
