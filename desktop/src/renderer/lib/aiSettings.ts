import type { AISettingsActionPlan, ConfigDefaults, ScanConfig } from "../../shared/api";
import { validAiSettingChange } from "../../shared/aiSettingsContract";
import { applyScanProfile } from "./settingsModel";

export function settingsForAi(config: ScanConfig): Record<string, unknown> {
  return {
    scan_profile: config.scanProfile,
    osint_profile: config.osintProfile,
    tool_settings: config.toolSettings,
    ai: {
      ...config.ai,
      apiKeyEnv: config.ai.apiKeyEnv || ""
    }
  };
}

function setNestedValue(source: Record<string, unknown>, path: string[], value: unknown): void {
  let current = source;
  for (const part of path.slice(0, -1)) {
    const next = current[part];
    if (!next || typeof next !== "object" || Array.isArray(next)) {
      current[part] = {};
    }
    current = current[part] as Record<string, unknown>;
  }
  current[path[path.length - 1]] = value;
}

export function applyAiPlanToConfig(config: ScanConfig, plan: AISettingsActionPlan, defaults: ConfigDefaults): ScanConfig {
  const seen = new Set<string>();
  if (plan.type !== "settings_recommendation" || plan.requires_user_approval !== true || (plan.risk_score_impact ?? 0) !== 0 || !Array.isArray(plan.changes) || !plan.changes.length || plan.changes.length > 64) {
    throw new Error("Geçersiz AI ayar önerisi.");
  }
  for (const change of plan.changes) {
    if (!change || !validAiSettingChange(change.path, change.proposed) || seen.has(change.path)) throw new Error("AI ayar değeri doğrulamadan geçmedi.");
    seen.add(change.path);
  }
  let next = structuredClone(config) as ScanConfig;
  // Apply the preset first, then explicit overrides, regardless of model row order.
  const profile = plan.changes.find((change) => change.path === "scan_profile")?.proposed;
  if (profile === "fast" || profile === "balanced" || profile === "slow") {
    next = applyScanProfile(next, defaults, profile);
    // A traffic recommendation must preserve operator-owned collector setup.
    next.toolSettings.osint = structuredClone(config.toolSettings.osint);
    next.toolSettings.ipNmap = structuredClone(config.toolSettings.ipNmap);
    next.tools.osint = config.tools.osint;
  }
  else if (profile === "custom") next.scanProfile = "custom";
  for (const change of plan.changes) {
    if (change.path === "scan_profile") {
      continue;
    }
    if (change.path === "osint_profile") {
      next.osintProfile = change.proposed as ScanConfig["osintProfile"];
      continue;
    }
    if (change.path.startsWith("tool_settings.")) {
      const parts = change.path.replace(/^tool_settings\./, "").split(".");
      setNestedValue(next.toolSettings as unknown as Record<string, unknown>, parts, change.proposed);
    }
  }
  if (plan.changes.some((change) => change.path.startsWith("tool_settings."))) next.scanProfile = "custom";
  next.tools = {
    ...next.tools,
    katana: next.toolSettings.katana.enabled,
    gobuster: next.toolSettings.gobuster.enabled,
    ffuf: next.toolSettings.ffuf.enabled,
    checks: next.toolSettings.checks.enabled,
    screenshots: next.toolSettings.screenshots.enabled,
    nuclei: next.toolSettings.nuclei.enabled
  };
  return next;
}
