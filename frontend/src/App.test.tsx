import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import { make_report } from "./test/report_fixture";

vi.mock("./components/charts", () => ({
  CoverageChart: () => <div aria-label="Coverage chart" />,
  SeverityChart: () => <div aria-label="Severity chart" />,
  TransportProfileCard: () => <div aria-label="Transport profile" />,
  InventoryChart: () => <div aria-label="Inventory chart" />,
}));

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
});

function render_app() {
  const query_client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
  return render(
    <QueryClientProvider client={query_client}>
      <App />
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

describe("capture upload", () => {
  it("rejects files that are not pcap captures", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation((request) => {
      const url = request_url(request);
      if (url.endsWith("/health")) return Promise.resolve(json_response({ status: "ok" }));
      if (url.endsWith("/cases")) return Promise.resolve(json_response({ cases: [] }));
      return Promise.resolve(json_response({ detail: "unexpected" }, 500));
    });
    render_app();
    await screen.findByTestId("no-case-selected");
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
      if (url.endsWith("/health")) return Promise.resolve(json_response({ status: "ok" }));
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
    render_app();
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
    expect(screen.getByRole("heading", { name: "Investigate in this order" })).toBeInTheDocument();
    expect(screen.getByRole("group", { name: /Case posture rings/ })).toBeInTheDocument();
    const certificate_ring = screen.getByRole("button", { name: /Ring 4 · inner, Certificate health:/ });
    fireEvent.pointerEnter(certificate_ring);
    expect(screen.getByRole("heading", { name: "Certificate health" })).toBeInTheDocument();
    expect(certificate_ring).toHaveAttribute("data-active", "true");
    fireEvent.click(screen.getByRole("tab", { name: /Evidence/ }));
    expect(await screen.findByRole("region", { name: "Observed Facts" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Network volume" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Flow integrity" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Evidence heatmaps" })).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Flows heatmap" })).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "TLS handshakes heatmap" })).toBeInTheDocument();
    const tls_cell = await screen.findByRole("button", { name: /TLSv10.*attention/ });
    fireEvent.click(tls_cell);
    expect(screen.getByRole("heading", { name: "TLS handshakes" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Flow path explorer" })).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /Network graph highlighting/ })).toBeInTheDocument();
  });

  it("shows a failed analysis without leaking the previous case", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation((request, init) => {
      const url = request_url(request);
      const method = request_method(request, init);
      if (url.endsWith("/health")) return Promise.resolve(json_response({ status: "ok" }));
      if (url.endsWith("/cases"))
        return Promise.resolve(
          json_response({ cases: [{ case_id: "case-a", title: "Case Alpha" }] }),
        );
      if (url.includes("/cases/case-a/report"))
        return Promise.resolve(json_response(make_report("case-a")));
      if (url.endsWith("/analyses") && method === "POST") {
        return Promise.resolve(
          json_response(make_job({ status: "running", stage: "deterministic_analysis" }), 202),
        );
      }
      if (url.endsWith("/analyses/r1"))
        return Promise.resolve(json_response(make_job({ status: "failed", error_message: "zeek failed" })));
      return Promise.resolve(json_response({ detail: "unexpected" }, 500));
    });
    const user = userEvent.setup();
    render_app();
    await screen.findByRole("option", { name: "Case Alpha" });
    await user.selectOptions(screen.getByLabelText("Select a case"), "case-a");
    expect(await screen.findByRole("heading", { name: "case-a" })).toBeInTheDocument();
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
      if (url.endsWith("/health"))
        return Promise.resolve(new Response(JSON.stringify({ status: "ok" }), { status: 200 }));
      if (url.endsWith("/cases"))
        return Promise.resolve(
          new Response(
            JSON.stringify({
              cases: [
                { case_id: "case-a", title: "Case Alpha" },
                { case_id: "case-b", title: "Case Bravo" },
              ],
            }),
            { status: 200 },
          ),
        );
      if (url.includes("case-a"))
        return Promise.resolve(new Response(JSON.stringify(make_report("case-a")), { status: 200 }));
      return new Promise<Response>((resolve) => {
        resolve_case_b = resolve;
      });
    });
    const user = userEvent.setup();
    render_app();

    await screen.findByRole("option", { name: "Case Alpha" });
    await user.selectOptions(screen.getByLabelText("Select a case"), "case-a");
    expect(await screen.findByRole("heading", { name: "case-a" })).toBeInTheDocument();

    await user.selectOptions(screen.getByLabelText("Select a case"), "case-b");
    expect(screen.queryByRole("heading", { name: "case-a" })).not.toBeInTheDocument();
    resolve_case_b?.(new Response(JSON.stringify(make_report("case-b")), { status: 200 }));
    expect(await screen.findByRole("heading", { name: "case-b" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Clear case" }));
    await waitFor(() => expect(screen.getByTestId("no-case-selected")).toBeInTheDocument());
    expect(screen.queryByRole("heading", { name: "case-b" })).not.toBeInTheDocument();
  });
});
