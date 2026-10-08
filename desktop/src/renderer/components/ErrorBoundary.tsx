import { t } from "../lib/i18n";
import React from "react";

interface ErrorBoundaryProps {
  children: React.ReactNode;
  title?: string;
  compact?: boolean;
  resetKey?: string;
  runDir?: string;
  onRetry?: () => void;
  onReturnDashboard?: () => void;
}

interface ErrorBoundaryState {
  error: Error | null;
}

export default class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo): void {
    console.error("[renderer] UI boundary caught error", error, info.componentStack);
  }

  componentDidUpdate(previousProps: ErrorBoundaryProps): void {
    if (this.state.error && previousProps.resetKey !== this.props.resetKey) {
      this.setState({ error: null });
    }
  }

  render(): React.ReactNode {
    const { error } = this.state;
    if (!error) return this.props.children;
    return (
      <section className={`ui-error-card ${this.props.compact ? "compact" : ""}`}>
        <span className="micro-label">{t("Renderer Error")}</span>
        <h2>{this.props.title || "UI bölümü yüklenemedi"}</h2>
        <p>{t("Bu bölüm hata verdi, fakat ReconBot arayüzü çalışmaya devam eder.")}</p>
        <code>{error.message || "Unknown renderer error"}</code>
        <div className="ui-error-actions">
          {this.props.onRetry ? (
            <button
              type="button"
              className="primary"
              onClick={() => {
                this.setState({ error: null });
                this.props.onRetry?.();
              }}
            >
              {t("Retry")}</button>
          ) : (
            <button type="button" className="primary" onClick={() => window.location.reload()}>
              {t("Reload UI")}</button>
          )}
          {this.props.onReturnDashboard && (
            <button type="button" onClick={this.props.onReturnDashboard}>{t("Return to Dashboard")}</button>
          )}
          {this.props.runDir && (
            <button type="button" onClick={() => void window.reconbot.openPath(this.props.runDir || "")}>{t("Open Run Folder")}</button>
          )}
        </div>
      </section>
    );
  }
}
