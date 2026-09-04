import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import { make_report } from "./test/report_fixture";

vi.mock("./components/charts", () => ({
  CoverageChart: () => <div aria-label="Coverage chart" />,
  SeverityChart: () => <div aria-label="Severity chart" />,
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

describe("case isolation", () => {
  it("does not retain a previous case after clear or switch", async () => {
    let resolve_case_b: ((response: Response) => void) | undefined;
    vi.spyOn(globalThis, "fetch").mockImplementation((request) => {
      const url = request instanceof Request ? request.url : String(request);
      if (url.endsWith("/health"))
        return Promise.resolve(
          new Response(JSON.stringify({ status: "ok" }), { status: 200 }),
        );
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
        return Promise.resolve(
          new Response(JSON.stringify(make_report("case-a")), { status: 200 }),
        );
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
    resolve_case_b?.(
      new Response(JSON.stringify(make_report("case-b")), { status: 200 }),
    );
    expect(await screen.findByRole("heading", { name: "case-b" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Clear case" }));
    await waitFor(() =>
      expect(screen.getByTestId("no-case-selected")).toBeInTheDocument(),
    );
    expect(screen.queryByRole("heading", { name: "case-b" })).not.toBeInTheDocument();
  });
});
