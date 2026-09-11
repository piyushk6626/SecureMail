import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import { make_report } from "./test/report_fixture";

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
});

function render_app(path = "/cases") {
  const query_client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
  return render(
    <QueryClientProvider client={query_client}>
      <MemoryRouter initialEntries={[path]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function json_response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function request_url(request: RequestInfo | URL): string {
  if (typeof request === "string") return request;
  if (request instanceof URL) return request.href;
  return request.url;
}

function request_method(request: RequestInfo | URL, init?: RequestInit): string {
  if (request instanceof Request) return request.method;
  return init?.method ?? "GET";
}

function make_job(overrides: Record<string, unknown> = {}) {
  return {
    run_id: "r1",
    case_id: "mail-abcd1234",
    status: "queued",
    stage: "intake",
    original_filename: "mail.pcapng",
    policy_profile: "ietf_current",
    created_at: "2026-09-05T00:00:00Z",
    updated_at: "2026-09-05T00:00:00Z",
    artifacts: { json: false, html: false, pdf: false },
    cancel_requested: false,
    ...overrides,
  };
}

function assign_files(input: HTMLInputElement, file: File): void {
  Object.defineProperty(input, "files", { configurable: true, value: [file] });
  fireEvent.change(input);
}

async function open_catalog_case(label: string, user: ReturnType<typeof userEvent.setup>): Promise<void> {
  const card = screen.getAllByTestId("catalog-case").find((node) => node.textContent.includes(label));
  if (!card) throw new Error(`Missing catalog card: ${label}`);
  await user.click(within(card).getByRole("button", { name: "Open case" }));
}

describe("capture upload", () => {
  it("rejects files that are not pcap captures", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation((request) => {
      const url = request_url(request);
      if (url.endsWith("/cases")) return Promise.resolve(json_response({ cases: [] }));
      return Promise.resolve(json_response({ detail: "unexpected" }, 500));
    });
    render_app("/upload");
    expect(await screen.findByRole("heading", { name: "Upload a capture" })).toBeInTheDocument();
    assign_files(
      screen.getByLabelText("Upload capture"),
      new File(["{}"], "note.json", { type: "application/json" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent("Choose a .pcap or .pcapng capture.");
  });

  it("polls a completed run and shows HTML/PDF downloads", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation((request, init) => {
      const url = request_url(request);
      const method = request_method(request, init);
      if (url.endsWith("/cases")) return Promise.resolve(json_response({ cases: [] }));
      if (url.endsWith("/analyses") && method === "POST")
        return Promise.resolve(json_response(make_job(), 202));
      if (url.endsWith("/analyses/r1"))
        return Promise.resolve(
          json_response(
            make_job({
              status: "completed",
              stage: "publication",
              artifacts: { json: true, html: true, pdf: true },
            }),
          ),
        );
      if (url.endsWith("/analyses/r1/report"))
        return Promise.resolve(json_response(make_report("mail-abcd1234")));
      return Promise.resolve(json_response({ detail: "unexpected" }, 500));
    });
    render_app("/upload");
    const bytes = new Uint8Array([0x0a, 0x0d, 0x0d, 0x0a, 0x00]);
    assign_files(
      screen.getByLabelText("Upload capture"),
      new File([bytes], "mail.pcapng", { type: "application/octet-stream" }),
    );
    expect(await screen.findByRole("heading", { name: "mail-abcd1234" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Download HTML" })).toHaveAttribute(
      "href",
      "/api/v1/analyses/r1/report.html",
    );
    expect(screen.getByRole("link", { name: "Download PDF" })).toHaveAttribute(
      "href",
      "/api/v1/analyses/r1/report.pdf",
    );
    expect(screen.getByRole("region", { name: "Assessment trust" })).toBeInTheDocument();
    expect(screen.getByTestId("trust-limitations")).toHaveTextContent(
      "Missing, conflicting, encrypted, or incomplete evidence is unresolved scope",
    );
    expect(screen.getByRole("heading", { name: "What needs action, where" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Acknowledge limits and continue" }));
    expect(screen.queryByTestId("trust-limitations")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: /Evidence/ }));
    expect(await screen.findByRole("heading", { name: "Evidence workspace" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Presented certificate chains" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Flow evidence" })).toBeInTheDocument();
  });

  it("shows a failed analysis without leaking the previous case", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation((request, init) => {
      const url = request_url(request);
      const method = request_method(request, init);
      if (url.endsWith("/cases"))
        return Promise.resolve(json_response({ cases: [{ case_id: "case-a", title: "Case Alpha" }] }));
      if (url.includes("/cases/case-a/report")) return Promise.resolve(json_response(make_report("case-a")));
      if (url.endsWith("/analyses") && method === "POST") {
        return Promise.resolve(json_response(make_job({ status: "running", stage: "deterministic_analysis" }), 202));
      }
      if (url.endsWith("/analyses/r1"))
        return Promise.resolve(json_response(make_job({ status: "failed", error_message: "zeek failed" })));
      return Promise.resolve(json_response({ detail: "unexpected" }, 500));
    });
    const user = userEvent.setup();
    render_app("/cases");
    await screen.findByRole("heading", { name: "Case Alpha" });
    await open_catalog_case("Case Alpha", user);
    expect(await screen.findByRole("heading", { name: "case-a" })).toBeInTheDocument();
    await user.click(screen.getByRole("link", { name: "Upload capture" }));
    const bytes = new Uint8Array([0x0a, 0x0d, 0x0d, 0x0a, 0x00]);
    assign_files(
      screen.getByLabelText("Upload capture"),
      new File([bytes], "mail.pcapng", { type: "application/octet-stream" }),
    );
    expect(await screen.findByText("Analysis failed")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "case-a" })).not.toBeInTheDocument();
    expect(screen.getByText("zeek failed")).toBeInTheDocument();
  });
});

describe("case isolation", () => {
  it("does not retain a previous case after clear or switch", async () => {
    let resolve_case_b: ((response: Response) => void) | undefined;
    vi.spyOn(globalThis, "fetch").mockImplementation((request) => {
      const url = request_url(request);
      if (url.endsWith("/cases"))
        return Promise.resolve(
          json_response({
            cases: [
              { case_id: "case-a", title: "Case Alpha" },
              { case_id: "case-b", title: "Case Bravo" },
            ],
          }),
        );
      if (url.includes("/cases/case-a/report")) return Promise.resolve(json_response(make_report("case-a")));
      return new Promise<Response>((resolve) => {
        resolve_case_b = resolve;
      });
    });
    const user = userEvent.setup();
    render_app("/cases");

    await screen.findByRole("heading", { name: "Case Alpha" });
    await open_catalog_case("Case Alpha", user);
    expect(await screen.findByRole("heading", { name: "case-a" })).toBeInTheDocument();

    await user.click(screen.getByRole("link", { name: "Back to catalog" }));
    await waitFor(() => expect(screen.getByTestId("no-case-selected")).toBeInTheDocument());
    expect(screen.queryByRole("heading", { name: "case-a" })).not.toBeInTheDocument();

    await open_catalog_case("Case Bravo", user);
    expect(screen.queryByRole("heading", { name: "case-a" })).not.toBeInTheDocument();
    resolve_case_b?.(json_response(make_report("case-b")));
    expect(await screen.findByRole("heading", { name: "case-b" })).toBeInTheDocument();

    await user.click(screen.getByRole("link", { name: "Back to catalog" }));
    await waitFor(() => expect(screen.getByTestId("no-case-selected")).toBeInTheDocument());
    expect(screen.queryByRole("heading", { name: "case-b" })).not.toBeInTheDocument();
  });
});

describe("dashboard shell", () => {
  it("renders the SecureMail logo and omits removed header controls", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation((request) => {
      const url = request_url(request);
      if (url.endsWith("/cases")) return Promise.resolve(json_response({ cases: [] }));
      return Promise.resolve(json_response({ detail: "unexpected" }, 500));
    });
    render_app("/cases");
    expect(await screen.findByRole("img", { name: "SecureMail" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Upload capture" })).toBeInTheDocument();
    expect(screen.queryByText("API online")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Portfolio$/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Case$/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /theme/i })).not.toBeInTheDocument();
  });
});
