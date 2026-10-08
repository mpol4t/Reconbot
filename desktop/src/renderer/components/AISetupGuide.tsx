import { t } from "../lib/i18n";
import { Bot, CheckCircle2, Server, Settings2, X } from "lucide-react";
import type { AIConfig, AIStatus } from "../../shared/api";
import { getEffectiveAiModel, normalizeAiConfig } from "../lib/settingsModel";

interface AISetupHelpCardProps {
  aiConfig: AIConfig;
  aiStatus?: AIStatus;
  onTestConnection: () => void;
  onOpenSettings: () => void;
  onOpenGuide?: () => void;
  onDisableAi: () => void;
}

interface AISetupGuideProps {
  open: boolean;
  aiConfig: AIConfig;
  aiStatus?: AIStatus;
  onClose: () => void;
  onTestConnection: () => void;
  onOpenSettings: () => void;
  onDisableAi: () => void;
}

export function AISetupHelpCard({
  aiConfig,
  aiStatus,
  onTestConnection,
  onOpenSettings,
  onOpenGuide,
  onDisableAi
}: AISetupHelpCardProps): JSX.Element {
  const safeAiConfig = normalizeAiConfig(aiConfig);
  const effectiveModel = getEffectiveAiModel(safeAiConfig);
  return (
    <section className="ai-setup-card">
      <header>
        <span className="micro-label"><Server size={13} /> {" "}{t("Yerel AI çalışmıyor")}</span>
        <h3>{t("Yerel AI endpoint'e ulaşılamıyor")}</h3>
        <p>
          {t("ReconBot AI yerel OpenAI-compatible endpoint'e bağlanamadı. ReconBot normal çalışmaya devam eder; AI sohbeti için local modeli başlatman gerekir.")}</p>
      </header>
      {aiStatus && (
        <div className={`ai-status-callout state-${aiStatus.connection}`}>
          <strong>{t(aiStatus.user_message_tr)}</strong>
          <small>{t(aiStatus.operator_action_tr)}</small>
        </div>
      )}
      <div className="ai-setup-options">
        <article>
          <strong>{t("Option 1: LM Studio")}</strong>
          <ol>
            <li>{t("LM Studio'yu aç.")}</li>
            <li>{t("Modeli yükle:")}{" "}<code>{effectiveModel}</code></li>
            <li>{t("Local Server / Developer Server bölümünü aç.")}</li>
            <li>{t("Server adresinin şu olduğundan emin ol:")}{" "}<code>{safeAiConfig.baseUrl}</code></li>
            <li>{t("ReconBot'ta \"Bağlantıyı Test Et\" butonuna bas.")}</li>
          </ol>
        </article>
        <article>
          <strong>{t("Option 2: OpenAI-compatible server")}</strong>
          <ol>
            <li>{t("OpenAI-compatible chat completions endpoint başlat.")}</li>
            <li>{t("Base URL değerini Settings > AI içinden ayarla.")}</li>
            <li>{t("Model adını Settings > AI içinden ayarla.")}</li>
            <li>{t("\"Bağlantıyı Test Et\" butonuna bas.")}</li>
          </ol>
        </article>
      </div>
      <div className="ai-setup-actions">
        <button type="button" className="primary" onClick={onTestConnection}><CheckCircle2 size={14} /> {" "}{t("Bağlantıyı Test Et")}</button>
        <button type="button" onClick={onOpenSettings}><Settings2 size={14} /> {" "}{t("AI Ayarlarını Aç")}</button>
        {onOpenGuide && <button type="button" onClick={onOpenGuide}><Bot size={14} /> {" "}{t("Kurulum Rehberini Aç")}</button>}
        <button type="button" onClick={onDisableAi}>{t("AI'ı Devre Dışı Bırak")}</button>
      </div>
    </section>
  );
}

export default function AISetupGuide({
  open,
  aiConfig,
  aiStatus,
  onClose,
  onTestConnection,
  onOpenSettings,
  onDisableAi
}: AISetupGuideProps): JSX.Element | null {
  if (!open) return null;
  return (
    <div className="modal-backdrop ai-setup-backdrop" role="presentation">
      <section className="ai-setup-modal" role="dialog" aria-modal="true" aria-labelledby="ai-setup-title">
        <header className="ai-setup-modal-head">
          <div>
            <span className="micro-label"><Bot size={13} /> {" "}{t("RECONBOT AI")}</span>
            <h2 id="ai-setup-title">{t("Kurulum Rehberi")}</h2>
            <p>{t("ReconBot AI opsiyoneldir. ReconBot tarama, rapor ve ayar ekranları AI olmadan normal çalışır.")}</p>
          </div>
          <button type="button" className="icon-button" onClick={onClose} title={t("Kapat")}><X size={16} /></button>
        </header>
        <div className="ai-setup-principles">
          <div><strong>1</strong><span>{t("AI opsiyoneldir; startup'ı bloklamaz.")}</span></div>
          <div><strong>2</strong><span>{t("Cloud provider gerekmez; local OpenAI-compatible endpoint yeterlidir.")}</span></div>
          <div><strong>3</strong><span>{t("Model indirme veya kurulum otomatik yapılmaz.")}</span></div>
        </div>
        <AISetupHelpCard
          aiConfig={aiConfig}
          aiStatus={aiStatus}
          onTestConnection={onTestConnection}
          onOpenSettings={() => { onClose(); onOpenSettings(); }}
          onDisableAi={() => { onClose(); onDisableAi(); }}
        />
      </section>
    </div>
  );
}
