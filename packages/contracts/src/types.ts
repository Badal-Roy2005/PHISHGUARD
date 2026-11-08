import type {
  EngineName,
  EngineStatus,
  ErrorCode,
  ReportCategory,
  ReportStatus,
  RiskBand,
  ScanStatus,
  Severity,
} from "./enums.ts";

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  detail?: string;
  evidence_ref?: string | null;
}

export interface EngineReport {
  engine: EngineName;
  status: EngineStatus;
  findings: Finding[];
  evidence: Record<string, unknown>;
  source: string;
  duration_ms: number;
  error?: string | null;
}

export type Engines = Record<EngineName, EngineReport>;

export interface ScoreContribution {
  engine: EngineName;
  weight: number;
  value: number;
  note?: string;
}

export interface LikelihoodScore {
  score: number;
  band: Exclude<RiskBand, "insufficient_evidence">;
  contributions: ScoreContribution[];
}

export interface PosturePenalty {
  id: string;
  points: number;
  note?: string;
}

export interface PostureScore {
  score: number;
  grade: "A" | "B" | "C" | "D" | "F" | "unknown";
  penalties: PosturePenalty[];
}

export interface ConfidenceScore {
  score: number;
  engines_ok: number;
  engines_total: number;
  notes?: string[];
}

export interface RiskAssessment {
  score: number | null;
  band: RiskBand;
  likelihood: LikelihoodScore;
  posture: PostureScore;
  confidence: ConfidenceScore;
}

export interface ExplanationFactor {
  feature: string;
  value?: number | string | boolean | null;
  contribution?: number;
  direction: "increases_risk" | "decreases_risk" | "informational";
  source: EngineName;
}

export interface Explanation {
  top_factors: ExplanationFactor[];
  summary: string;
}

export interface ScanOptions {
  include_intel?: boolean;
  include_ct?: boolean;
  timeout_ms?: number;
}

export interface ScanRequest {
  url: string;
  options?: ScanOptions;
}

export interface ScanAccepted {
  scan_id: string;
  status: "queued" | "running";
  poll_after_ms: number;
}

export interface ScanResult {
  scan_id: string;
  url: string;
  normalized_url: string;
  status: ScanStatus;
  created_at: string;
  completed_at?: string | null;
  duration_ms?: number | null;
  risk: RiskAssessment | null;
  engines: Engines;
  explanation: Explanation | null;
  evidence: Record<string, unknown>;
}

export interface ErrorBody {
  code: ErrorCode;
  message: string;
  request_id?: string;
  details?: Record<string, unknown>;
}

export interface ErrorResponse {
  error: ErrorBody;
}

export interface ModelMetrics {
  accuracy?: number;
  precision?: number;
  recall?: number;
  f1?: number;
  roc_auc?: number;
  pr_auc?: number;
}

export interface ModelMetadata {
  name: string;
  version: string;
  trained_at?: string | null;
  dataset?: string | null;
  feature_contract_version: string;
  label_map?: { "0": "phishing"; "1": "legitimate" };
  metrics?: ModelMetrics;
  artifact_sha256?: string | null;
}

export interface Contribution {
  feature: string;
  value?: number | string | boolean | null;
  shap: number;
}

export interface PredictRequest {
  features: Record<string, number | boolean | string>;
  explain?: boolean;
  model_version?: string | null;
}

export interface PredictResponse {
  label: "phishing" | "legitimate" | "unknown";
  probability_phishing: number;
  contributions?: Contribution[];
  missing_features?: string[];
  status: "ok" | "partial" | "unknown";
  model: ModelMetadata;
}

export type FeatureDType = "number" | "integer" | "boolean" | "category";
export type FeatureLiveSource = "url" | "tls" | "http" | "intel" | "derived" | "dataset_only";
export type FeatureDefaultPolicy = "reject" | "unknown" | "neutral";

export interface FeatureContractEntry {
  name: string;
  dataset_column: string;
  dtype: FeatureDType;
  required: boolean;
  live_source: FeatureLiveSource;
  default_policy: FeatureDefaultPolicy;
  notes?: string;
}

export interface FeatureContract {
  version: string;
  model_version: string;
  dataset?: {
    name?: string;
    rows?: number;
    feature_count?: number;
    class_counts?: Record<string, number>;
  };
  label_map: { "0": "phishing"; "1": "legitimate" };
  features: FeatureContractEntry[];
}

export interface CreateReportRequest {
  url: string;
  category: ReportCategory;
  description: string;
  evidence?: Record<string, unknown>;
}

export interface Report {
  id: string;
  url: string;
  category: ReportCategory;
  description?: string;
  status: ReportStatus;
  created_at: string;
  reporter_id?: string | null;
  vote_count: number;
}
