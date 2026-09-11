import type {
  CanonicalReport,
  EvidenceState,
  FindingSeverity,
} from "../types/canonical_report.generated";

export type { CanonicalReport, EvidenceState, FindingSeverity };

export interface CaseSummary {
  case_id: string;
  title?: string | null;
  generated_at?: string | null;
  risk_score?: number | null;
  finding_count?: number;
  severity_counts?: {
    high: number;
    medium: number;
    low: number;
    informational: number;
  };
  unknown_count?: number;
  not_observable_count?: number;
  advisory_present?: boolean;
  analyst_conclusions_present?: boolean;
  assessment_state?: "complete" | "limited" | "none";
  protocols?: string[];
}

export interface CaseCatalog {
  cases: CaseSummary[];
}

export function case_label(item: CaseSummary): string {
  const title = item.title?.trim();
  return title && title.length > 0 ? title : item.case_id;
}

export type AnalysisStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export interface AnalysisJob {
  run_id: string;
  case_id: string;
  status: AnalysisStatus;
  stage: string;
  capture_sha256?: string | null;
  original_filename: string;
  policy_profile: string;
  expected_hostname?: string | null;
  created_at: string;
  updated_at: string;
  error_message?: string | null;
  artifacts: { json: boolean; html: boolean; pdf: boolean };
  cancel_requested: boolean;
}

export const severity_order: Record<FindingSeverity, number> = {
  high: 4,
  medium: 3,
  low: 2,
  informational: 1,
};

export function normalize_case_catalog(payload: unknown): CaseCatalog {
  if (Array.isArray(payload)) return { cases: payload.filter(is_case_summary) };
  if (!is_record(payload) || !Array.isArray(payload.cases)) return { cases: [] };
  return { cases: payload.cases.filter(is_case_summary) };
}

function is_case_summary(value: unknown): value is CaseSummary {
  return (
    is_record(value) &&
    typeof value.case_id === "string" &&
    (value.risk_score === undefined || value.risk_score === null || typeof value.risk_score === "number")
  );
}

export function is_record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function is_canonical_report(value: unknown): value is CanonicalReport {
  if (!is_record(value)) return false;
  if (value.schema_version !== "securemail.report/v1") return false;
  if (!is_record(value.manifest) || !is_record(value.evidence)) return false;
  return is_record(value.limitations);
}
