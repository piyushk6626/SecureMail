import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "@fontsource-variable/inter";
import "@fontsource-variable/jetbrains-mono";
import "./styles.css";
import App from "./App";

const query_client = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: false,
    },
  },
});

const root = document.getElementById("root");
if (!root) throw new Error("Application root is missing.");

createRoot(root).render(
  <StrictMode>
    <QueryClientProvider client={query_client}>
      <App />
    </QueryClientProvider>
  </StrictMode>,
);
