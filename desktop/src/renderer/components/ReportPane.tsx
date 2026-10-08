import { t } from "../lib/i18n";
import { useEffect, useMemo, useRef, useState } from "react";
import type { RunStateSnapshot } from "../../shared/api";

interface ReportPaneProps {
  runState: RunStateSnapshot;
  updateKey?: string;
  updateMessage?: string;
  onAskAi?: (mode: string, question: string) => void;
  onNavigateArtifacts: () => void;
  onNavigateValidation?: () => void;
  onRefreshState: () => void;
}

export default function ReportPane({
  runState,
  updateKey = "",
  updateMessage = "",
  onAskAi,
  onNavigateArtifacts,
  onNavigateValidation,
  onRefreshState
}: ReportPaneProps): JSX.Element {
  const { report } = runState;
  const [loadedMtime, setLoadedMtime] = useState(report.mtime || 0);
  const [reloadToken, setReloadToken] = useState(0);
  const [loadState, setLoadState] = useState<"idle" | "loading" | "loaded" | "failed">("idle");
  const [loadError, setLoadError] = useState("");
  const [updateNotice, setUpdateNotice] = useState("");
  const lastUpdateKey = useRef("");
  const reportIdentity = `${runState.currentRunDir}|${report.path}|${report.viewUrl}`;

  const reportSrc = useMemo(() => {
    if (!report.exists || !report.viewUrl) return "";
    const separator = report.viewUrl.includes("?") ? "&" : "?";
    const version = loadedMtime || report.mtime || 0;
    return `${report.viewUrl}${separator}run=${encodeURIComponent(runState.currentRunDir)}&v=${version}-${reloadToken}`;
  }, [loadedMtime, reloadToken, report.exists, report.mtime, report.viewUrl, runState.currentRunDir]);

  useEffect(() => {
    setLoadedMtime(report.exists ? report.mtime || 0 : 0);
    setReloadToken(0);
    setLoadState(report.exists && report.viewUrl ? "loading" : "idle");
    setLoadError("");
    setUpdateNotice("");
    lastUpdateKey.current = "";
    // A live rewrite is an update notification, not a navigation. Keep the
    // loaded document (and its scroll/depth/details state) until explicit reload.
  }, [reportIdentity, report.exists]);

  useEffect(() => {
    if (!updateKey || lastUpdateKey.current === updateKey) return;
    if (!report.exists || !report.viewUrl) return;
    lastUpdateKey.current = updateKey;
    // Enrichment updates must also leave an operator's reading session intact.
    setUpdateNotice(updateMessage || "Report updated");
  }, [updateKey, updateMessage, report.exists, report.mtime, report.viewUrl]);

  useEffect(() => {
    setLoadState(reportSrc ? "loading" : "idle");
    setLoadError("");
  }, [reportSrc]);

  const reportUpdated = Boolean(report.exists && report.mtime !== loadedMtime);
  const reportStatus = !runState.currentRunDir
    ? t("No run selected")
    : !report.exists
      ? report.status === "failed"
        ? t("Report generation failed: {detail}", {detail: report.failureReason || report.path})
        : t("Run exists but report.html is missing: {path}", {path: report.path})
      : loadState === "loaded"
        ? t("Report loaded: {path}", {path: report.path})
        : loadState === "failed"
          ? t("Report load failed: {detail}", {detail: loadError || report.path})
          : t("Report found: {path}", {path: report.path});

  const reload = (): void => {
    if (!report.exists || !report.viewUrl) return;
    setLoadedMtime(report.mtime || 0);
    setReloadToken((value) => value + 1);
  };

  const artifacts = runState.artifacts;
  const openArtifact = (kind: "runDir" | "rawLog" | "stateJson"): void => {
    const artifactPath = kind === "runDir"
      ? runState.currentRunDir
      : artifacts?.paths[kind] || "";
    if (artifactPath) void window.reconbot.openPath(artifactPath);
  };

  return (
    <section className="report-pane" data-testid="report-pane">
      <header className="report-toolbar cockpit-panel">
        <div>
          <span className="micro-label">{t("Report")}</span>
          <h2>{report.exists ? t("Embedded report view") : t("Report durumu")}</h2>
        </div>
        <div className="toolbar-actions">
          {updateNotice && <span className="updated">{updateNotice}</span>}
          {!updateNotice && reportUpdated && <span className="updated">{t("Report updated")}</span>}
          <button type="button" disabled={!report.exists || !report.viewUrl} onClick={reload}>
            {t("Reload")}</button>
          {onNavigateValidation && <button type="button" onClick={onNavigateValidation}>{t("SQLmap evidence")}</button>}
          <button type="button" disabled={!report.exists} onClick={() => onAskAi?.("report", t("Bu raporu AI ile açıkla. Önemli bulguları, kaynak kapsamını ve kesin olmayan noktaları ayır."))}>
            {t("AI ile açıkla")}</button>
          <button type="button" disabled={!report.exists} onClick={() => onAskAi?.("trust", t("Bu sonuç güvenilir mi? Partial coverage, source health ve false-positive riskini açıkla."))}>
            {t("Bu bölümü AI'a sor")}</button>
          <button type="button" disabled={!report.exists} onClick={() => onAskAi?.("finding", t("Bu bulgu gerçek mi? Yalnız mevcut rapor kanıtlarına göre değerlendir."))}>
            {t("Bu bulgu gerçek mi?")}</button>
          <button type="button" disabled={!report.exists} onClick={() => onAskAi?.("next", t("Bu rapora göre sonraki güvenli operatör adımı ne olmalı?"))}>
            {t("Sonraki adımı sor")}</button>
          <button type="button" disabled={!report.exists} onClick={() => void window.reconbot.openPath(report.path)}>
            {t("Open External")}</button>
          <button type="button" disabled={!report.path} onClick={() => void window.reconbot.copyText(report.path)}>
            {t("Copy Report Path")}</button>
        </div>
      </header>
      <div className={`report-status ${loadState}`}>
        <span>{reportStatus}</span>
      </div>
      {reportSrc ? (
        <iframe
          key={reportIdentity}
          title={t("ReconBot report")}
          sandbox="allow-scripts allow-same-origin allow-forms allow-popups"
          src={reportSrc}
          className="report-frame"
          onLoad={() => setLoadState("loaded")}
          onError={() => {
            setLoadState("failed");
            setLoadError("iframe failed to load report URL");
          }}
        />
      ) : (
        <div className="report-empty useful-report-empty">
          <div>
            <span className="micro-label">{report.status === "failed" ? t("Report failed") : t("Report unavailable")}</span>
            <h2>{t("Bu run için report.html mevcut değil.")}</h2>
            <p>
              {runState.completeness === "report_pending" || runState.completeness === "partial"
                ? t("Bu run kısmi veya tamamlanmamış durumda. Mevcut artifactleri inceleyebilir ve durumu yenileyebilirsiniz.")
                : t("Bu run henüz rapor üretmedi veya rapor dosyası kaldırılmış.")}
            </p>
            <dl>
              <div><dt>{t("Run directory")}</dt><dd><code>{runState.currentRunDir || t("No run selected")}</code></dd></div>
              <div><dt>{t("Run state")}</dt><dd>{runState.runState || "unknown"}</dd></div>
              <div><dt>{t("Completeness")}</dt><dd>{runState.completeness || "unknown"}</dd></div>
              <div><dt>{t("Historical")}</dt><dd>{runState.isHistorical ? t("yes") : t("no")}</dd></div>
            </dl>
            <div className="report-empty-actions">
              <button type="button" disabled={!artifacts?.exists.runDir} onClick={() => openArtifact("runDir")}>{t("Open Run Folder")}</button>
              <button type="button" disabled={!artifacts?.exists.rawLog} onClick={() => openArtifact("rawLog")}>{t("Open Log")}</button>
              <button type="button" disabled={!artifacts?.exists.stateJson} onClick={() => openArtifact("stateJson")}>{t("Open JSON")}</button>
              <button type="button" onClick={onNavigateArtifacts}>{t("Go to Artifacts")}</button>
              <button type="button" onClick={onRefreshState}>{t("Refresh state")}</button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
