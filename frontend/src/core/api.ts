import {
  is_canonical_report,
  normalize_case_catalog,
  type AnalysisJob,
  type CanonicalReport,
  type CaseCatalog,
  is_record,
} from "./model";

const api_root = "/api/v1";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function read_json(response: Response): Promise<unknown> {
  if (!response.ok) {
    const fallback = `Request failed (${response.status})`;
    const detail = await response.text().catch(() => "");
    throw new ApiError(detail || fallback, response.status);
  }
  return response.json() as Promise<unknown>;
}

export async function get_cases(input: { signal?: AbortSignal }): Promise<CaseCatalog> {
  const payload = await read_json(
    await fetch(`${api_root}/cases`, {
      headers: { Accept: "application/json" },
      signal: input.signal ?? null,
    }),
  );
  return normalize_case_catalog(payload);
}

export async function get_case_report(input: {
  case_id: string;
  signal?: AbortSignal;
}): Promise<CanonicalReport> {
  const payload = await read_json(
    await fetch(`${api_root}/cases/${encodeURIComponent(input.case_id)}/report`, {
      headers: { Accept: "application/json" },
      signal: input.signal ?? null,
    }),
  );
  if (!is_canonical_report(payload)) throw new ApiError("The API returned an invalid report.", 502);
  return payload;
}

export async function preview_report(input: { file: File }): Promise<CanonicalReport> {
  const payload = await read_json(
    await fetch(`${api_root}/reports/preview`, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: await input.file.arrayBuffer(),
    }),
  );
  if (!is_canonical_report(payload)) throw new ApiError("The file is not a canonical report.", 422);
  return payload;
}

function is_analysis_job(value: unknown): value is AnalysisJob {
  return (
    is_record(value) &&
    typeof value.run_id === "string" &&
    typeof value.case_id === "string" &&
    typeof value.status === "string" &&
    typeof value.stage === "string"
  );
}

export async function create_analysis(input: {
  file: File;
  policy_profile?: string;
  expected_hostname?: string;
  signal?: AbortSignal;
}): Promise<AnalysisJob> {
  const body = new FormData();
  body.append("file", input.file, input.file.name);
  body.append("policy_profile", input.policy_profile ?? "ietf_current");
  if (input.expected_hostname) body.append("expected_hostname", input.expected_hostname);
  const payload = await read_json(
    await fetch(`${api_root}/analyses`, {
      method: "POST",
      headers: { Accept: "application/json" },
      body,
      signal: input.signal ?? null,
    }),
  );
  if (!is_analysis_job(payload)) throw new ApiError("The API returned an invalid analysis job.", 502);
  return payload;
}

export async function get_analysis(input: {
  run_id: string;
  signal?: AbortSignal;
}): Promise<AnalysisJob> {
  const payload = await read_json(
    await fetch(`${api_root}/analyses/${encodeURIComponent(input.run_id)}`, {
      headers: { Accept: "application/json" },
      signal: input.signal ?? null,
    }),
  );
  if (!is_analysis_job(payload)) throw new ApiError("The API returned an invalid analysis job.", 502);
  return payload;
}

export async function get_analysis_report(input: {
  run_id: string;
  signal?: AbortSignal;
}): Promise<CanonicalReport> {
  const payload = await read_json(
    await fetch(analysis_report_url(input.run_id), {
      headers: { Accept: "application/json" },
      signal: input.signal ?? null,
    }),
  );
  if (!is_canonical_report(payload)) throw new ApiError("The API returned an invalid report.", 502);
  return payload;
}

export async function cancel_analysis(input: { run_id: string }): Promise<AnalysisJob> {
  const payload = await read_json(
    await fetch(`${api_root}/analyses/${encodeURIComponent(input.run_id)}/cancel`, {
      method: "POST",
      headers: { Accept: "application/json" },
    }),
  );
  if (!is_analysis_job(payload)) throw new ApiError("The API returned an invalid analysis job.", 502);
  return payload;
}

export function analysis_report_url(run_id: string): string {
  return `${api_root}/analyses/${encodeURIComponent(run_id)}/report`;
}

export function analysis_html_url(run_id: string): string {
  return `${api_root}/analyses/${encodeURIComponent(run_id)}/report.html`;
}

export function analysis_pdf_url(run_id: string): string {
  return `${api_root}/analyses/${encodeURIComponent(run_id)}/report.pdf`;
}

export function case_html_url(case_id: string): string {
  return `${api_root}/cases/${encodeURIComponent(case_id)}/report.html`;
}

export function case_pdf_url(case_id: string): string {
  return `${api_root}/cases/${encodeURIComponent(case_id)}/report.pdf`;
}
