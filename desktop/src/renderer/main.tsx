import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import ErrorBoundary from "./components/ErrorBoundary";
import "./types/api";
import "./styles/theme.css";
import "./styles/operator.css";
import "@xterm/xterm/css/xterm.css";

createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <ErrorBoundary title="ReconBot UI yüklenemedi">
      <App />
    </ErrorBoundary>
  </React.StrictMode>
);
