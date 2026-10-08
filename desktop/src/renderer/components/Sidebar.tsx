import reconbotIcon from "../../../resources/reconbot-icon.png";
import reconbotAiIcon from "../../../resources/reconbot-ai.svg";
import LanguageSelector from "./LanguageSelector";
import { t } from "../lib/i18n";
import {
  Bug,
  Database,
  KeyRound,
  PlugZap,
  FileText,
  FolderOpen,
  GitBranch,
  LayoutDashboard,
  Logs,
  MessageSquareText,
  Settings2,
  SlidersHorizontal,
  Sparkles,
  Terminal,
  Wand2
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import type { AIStatus, RunStateSnapshot } from "../../shared/api";

export type ActiveView = "dashboard" | "configure" | "terminal" | "report" | "artifacts" | "findings" | "pipeline" | "validation" | "authentication" | "settings";

interface SidebarProps {
  activeView: ActiveView;
  runState: RunStateSnapshot;
  aiStatus: AIStatus | null;
  aiSessionStarted: boolean;
  aiStatusLabel: string;
  aiModel: string;
  aiSuggestionReady: boolean;
  aiReportPromptEnabled: boolean;
  onNavigate: (view: ActiveView) => void;
  onOpenAi: () => void;
  onOpenAiSetup: () => void;
  onOpenAiSettings: () => void;
  onTestAiConnection: () => void;
  onAiQuickAction: (mode: string, question: string) => void;
}

const navItems: Array<{ view: ActiveView; label: string; sub: string; icon: LucideIcon }> = [
  { view: "dashboard", label: "Dashboard", sub: "Genel görünüm", icon: LayoutDashboard },
  { view: "configure", label: "Configure", sub: "Tarama ayarları", icon: SlidersHorizontal },
  { view: "terminal", label: "Terminal", sub: "Canlı konsol", icon: Terminal },
  { view: "report", label: "Report", sub: "Rapor görüntüleyici", icon: FileText },
  { view: "artifacts", label: "Artifacts", sub: "Çıktılar ve dosyalar", icon: FolderOpen },
  { view: "findings", label: "Findings", sub: "Canlı bulgular", icon: Bug },
  { view: "validation", label: "Validation", sub: "SQLmap", icon: Database },
  { view: "authentication", label: "Authentication", sub: "Login testing", icon: KeyRound },
  { view: "pipeline", label: "Threat Pipeline", sub: "Saldırı zinciri", icon: GitBranch },
  { view: "settings", label: "Settings", sub: "Ayarlar", icon: Settings2 }
];


function shortModel(model: string): string {
  return model.split("@")[0].replace("-uncensored-hauhaucs-aggressive", "");
}

export default function Sidebar({
  activeView,
  runState,
  aiStatus,
  aiSessionStarted,
  aiStatusLabel,
  aiModel,
  aiSuggestionReady,
  aiReportPromptEnabled,
  onNavigate,
  onOpenAi,
  onOpenAiSetup,
  onOpenAiSettings,
  onTestAiConnection,
  onAiQuickAction
}: SidebarProps): JSX.Element {
  const reportReady = Boolean(runState.report.exists);
  const ready = Boolean(aiStatus?.ready);
  const disabled = aiStatus?.connection === "disabled";
  const busy = aiStatus?.connection === "busy";
  const queued = aiStatus?.connection === "queued";
  const timedOut = aiStatus?.connection === "timeout";
  const reasoningWithoutFinal = aiStatus?.connection === "reasoning_without_final";
  const checking = !aiStatus || aiStatus.connection === "checking" || aiStatus.connection === "checking_connection" || aiStatus.connection === "needs_recheck";
  const unavailable = Boolean(aiStatus && !aiStatus.ready && !disabled && !checking && !busy && !queued && !timedOut && !reasoningWithoutFinal);
  const aiStateClass = busy ? "busy" : queued ? "queued" : timedOut ? "timeout" : reasoningWithoutFinal ? "timeout" : ready && ((reportReady && aiReportPromptEnabled) || aiSuggestionReady) ? "ready" : checking ? "checking" : unavailable ? "unavailable" : disabled ? "disabled" : "";
  const dynamicStatus = aiSuggestionReady
    ? "Ayar önerisi hazır"
    : busy
      ? "Model yanıt üretiyor"
      : queued
        ? "İstek sırada"
        : timedOut
          ? "Model yavaş yanıt verdi"
          : reasoningWithoutFinal
            ? "Model final cevap üretmedi"
          : ready && reportReady && aiReportPromptEnabled
      ? "Rapor hazır · Özet çıkarabilirim"
      : ready
        ? "Yerel model bağlı"
        : disabled
          ? "AI devre dışı"
          : checking
            ? "AI bağlantısı kontrol ediliyor..."
            : aiStatus?.connection === "model_missing"
              ? "Model yüklü değil veya adı eşleşmiyor"
              : aiStatus?.connection === "invalid_response"
                ? "Endpoint uyumsuz"
                : "AI bağlantısı yok";
  const primaryAction = ready && reportReady && !aiSessionStarted
    ? { label: "Raporu Açıkla", icon: Sparkles, onClick: () => onAiQuickAction("report", t("Bu raporu kısa bir operatör brifingi olarak özetle")) }
    : ready
      ? { label: "Sohbeti Aç", icon: MessageSquareText, onClick: onOpenAi }
      : disabled
        ? { label: "AI Ayarları", icon: Settings2, onClick: onOpenAiSettings }
        : { label: "Nasıl çalıştırılır?", icon: Sparkles, onClick: onOpenAiSetup };
  const PrimaryIcon = primaryAction.icon;
  const displayModel = aiModel || aiStatus?.effectiveModel || aiStatus?.effective_model || aiStatus?.model || "";
  const modelBadge = disabled ? "disabled" : shortModel(displayModel);
  return (
    <aside className="sidebar">
      <div className="brand-lockup">
        <div className="bot-mark" aria-hidden="true">
          <img className="reconbot-brand-icon" src={reconbotIcon} alt="" />
        </div>
        <div>
          <strong>{t("RECONBOT")}</strong>
          <small>{t("Operator Console")}</small>
        </div>
      </div>

      <span className="navigation-label">{t("Workspace")}</span>
      <nav className="nav-rail" aria-label={t("Workspace")}>
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
          <button
            key={item.view}
            className={activeView === item.view ? "active" : ""}
            data-view={item.view}
            aria-current={activeView === item.view ? "page" : undefined}
            onClick={() => onNavigate(item.view)}
            type="button"
          >
            <span className="nav-mark"><Icon size={18} strokeWidth={1.8} /></span>
            <span>
              <strong>{t(item.label)}</strong>
              <small>{t(item.sub)}</small>
            </span>
          </button>
          );
        })}
      </nav>

      <div className={`ai-hub ${aiStateClass}`}>
        <div className="ai-hub-top">
          <div className="ai-core-icon" aria-hidden="true">
            <img className="reconbot-brand-icon" src={reconbotAiIcon} alt="" />
            <span />
          </div>
          <div>
            <strong>{t("RECONBOT AI")}</strong>
            <small>{t("Operator Copilot")}</small>
          </div>
        </div>
        <div className="ai-hub-status">
          <span className={ready ? "dot live" : "dot"} />
          <span>{t(dynamicStatus)}</span>
        </div>
        <div className="ai-model-badge">
          <span>{modelBadge}</span>
          <small>{t(aiStatusLabel)}</small>
        </div>
        <div className="ai-hub-actions">
          <button type="button" className="primary-ai-action" onClick={primaryAction.onClick}><PrimaryIcon size={14} /> {t(primaryAction.label)}</button>
          {unavailable && <button type="button" onClick={onTestAiConnection}><PlugZap size={14} /> {" "}{t("Bağlantıyı Test Et")}</button>}
          {ready && <button type="button" disabled={!runState.currentRunDir} onClick={() => onAiQuickAction("logs", t("Logları incele ve partial scan varsa troubleshoot et."))}><Logs size={14} /> {" "}{t("Logları Yorumla")}</button>}
          {ready && <button type="button" onClick={() => onAiQuickAction("settings", t("Daha yavaş ama daha güvenli ve düşük trafikli tarama ayarı öner."))}><Wand2 size={14} /> {" "}{t("Ayar Öner")}</button>}
        </div>
      </div>
      <LanguageSelector />
    </aside>
  );
}
