import {
  is_canonical_report,
  normalize_case_catalog,
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

export async function get_health(input: { signal?: AbortSignal }): Promise<"ok"> {
  const payload = await read_json(
    await fetch(`${api_root}/health`, {
      headers: { Accept: "application/json" },
      signal: input.signal ?? null,
    }),
  );
  if (!is_record(payload) || payload.status !== "ok")
    throw new ApiError("The API health response is invalid.", 502);
  return "ok";
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
