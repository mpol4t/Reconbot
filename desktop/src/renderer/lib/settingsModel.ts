import type { ConfigDefaults, RunMode, ScanConfig, ScanProfile, ToolSettings, TrafficProfile } from "../../shared/api";
import { DEFAULT_AI_CONFIG, getEffectiveAiModel, normalizeAiConfig } from "../../shared/aiSettingsContract";
import { DEFAULT_METADATA_FEED, normalizeMetadataFeed } from "../../shared/metadataFeed";

export const defaultAiConfig = DEFAULT_AI_CONFIG;
export { getEffectiveAiModel, normalizeAiConfig };

function boolValue(value: unknown, fallback: boolean): boolean {
  return typeof value === "boolean" ? value : fallback;
}

function stringValue(value: unknown, fallback: string): string {
  return typeof value === "string" ? value : fallback;
}

function numberValue(value: unknown, fallback: number): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export const scanProfiles: Exclude<ScanProfile, "custom">[] = ["fast", "balanced", "slow"];
export const runModes: Array<{ value: RunMode; label: string; description: string }> = [
  { value: "normal_scan_only", label: "Normal Scan Only", description: "Run the existing scanner pipeline without OSINT." },
  { value: "osint_only", label: "OSINT Only", description: "Skip active scanners and run safe passive OSINT enrichment." },
  { value: "normal_scan_plus_osint", label: "Normal Scan + OSINT", description: "Run the normal scan, then attach passive OSINT enrichment." }
];

export function trafficFromScanProfile(profile: ScanProfile): TrafficProfile {
  if (profile === "fast") return "fast";
  if (profile === "slow") return "safe";
  return "balanced";
}

function enabledTools(defaults: ConfigDefaults, profile: ScanProfile): Record<string, boolean> {
  const base = Object.fromEntries(defaults.tools.map((tool) => [tool.name, tool.enabled]));
  if (profile === "fast") {
    return {
      ...base,
      ffuf: false,
      historical_urls: false,
      screenshots: false,
      nuclei: true,
      checks: true
    };
  }
  if (profile === "slow") {
    return {
      ...base,
      ffuf: true,
      historical_urls: true,
      screenshots: true,
      nuclei: true,
      checks: true
    };
  }
  return base;
}

export function toolSettingsForProfile(defaults: ConfigDefaults, profile: ScanProfile): ToolSettings {
  const tools = enabledTools(defaults, profile);
  const fast = profile === "fast";
  const slow = profile === "slow";
  return {
    katana: {
      enabled: Boolean(tools.katana),
      maxDepth: fast ? 2 : slow ? 4 : 3,
      timeout: fast ? 20 : slow ? 75 : 45,
      rateLimit: fast ? 0 : slow ? 2 : 5,
      maxUrls: fast ? 75 : slow ? 500 : 200
    },
    gobuster: {
      enabled: Boolean(tools.gobuster),
      wordlistProfile: fast ? "small" : slow ? "large" : "medium",
      threads: fast ? 20 : slow ? 8 : 12,
      timeout: fast ? 8 : slow ? 20 : 12,
      extensions: ""
    },
    ffuf: {
      enabled: Boolean(tools.ffuf),
      wordlistProfile: fast ? "small" : slow ? "large" : "medium",
      rateLimit: fast ? 120 : slow ? 30 : 60,
      timeout: fast ? 8 : slow ? 20 : 12,
      maxResults: fast ? 50 : slow ? 500 : 150
    },
    checks: {
      enabled: Boolean(tools.checks),
      timeout: fast ? 5 : slow ? 12 : 8,
      followRedirects: true,
      maxBodySize: slow ? 1048576 : 524288
    },
    screenshots: {
      enabled: Boolean(tools.screenshots),
      timeout: fast ? 45 : slow ? 120 : 90,
      maxScreenshots: fast ? 5 : slow ? 25 : 10
    },
    nuclei: {
      enabled: Boolean(tools.nuclei),
      severityFilter: fast ? "critical,high,medium" : "critical,high,medium,low,info",
      templateProfile: fast ? "safe" : slow ? "broad" : "standard",
      rateLimit: fast ? 25 : slow ? 8 : 15,
      timeout: fast ? 45 : slow ? 120 : 75,
      maxTemplates: fast ? 500 : slow ? 3000 : 1500
    },
    ipNmap: {
      enabled: false,
      mode: fast ? "fast" : slow ? "deep" : "basic",
      topPorts: fast ? 100 : slow ? 1000 : 250,
      timeout: fast ? 30 : slow ? 180 : 90
    },
    osint: {
      enabled: false,
      mode: "safe_mvp",
      includeCertificateTransparency: true,
      includeKnownBreachCatalog: true,
      includeHistoricalUrls: true,
      includePublicCodeReferences: true,
      includeSearchDorkSuggestions: true,
      includeInfrastructureIntelligence: true,
      includeOrganizationIntelligence: true,
      maxSignals: fast ? 25 : slow ? 100 : 50,
      timeout: fast ? 15 : slow ? 60 : 30,
      passiveOnly: true,
      sources: {
        githubCodeSearch: {
          enabled: true,
          apiKeyEnv: "GITHUB_TOKEN",
          apiKeyConfigured: false
        },
        wayback: {
          enabled: true,
          timeout: fast ? 8 : slow ? 30 : 15,
          retryCount: fast ? 0 : 1
        },
        crtsh: {
          enabled: true,
          timeout: fast ? 8 : slow ? 30 : 15,
          retryCount: fast ? 0 : 1
        },
        knownBreachCatalog: {
          enabled: true
        }
      },
      leakSources: {
        metadataFeed: { ...DEFAULT_METADATA_FEED }
      },
      darkweb: {
        enabled: true,
        manualMetadataImport: {
          enabled: false,
          sourceName: "",
          filePath: "",
          maxResults: 25
        },
        customHttpsProvider: {
          enabled: false,
          providerUrl: "",
          apiKeyEnv: "DARKWEB_METADATA_TOKEN",
          apiKeyConfigured: false,
          maxResults: 25,
          timeout: 10
        }
      }
    }
  };
}

export function applyScanProfile(config: ScanConfig, defaults: ConfigDefaults, profile: Exclude<ScanProfile, "custom">): ScanConfig {
  const toolSettings = toolSettingsForProfile(defaults, profile);
  return {
    ...config,
    scanProfile: profile,
    trafficProfile: trafficFromScanProfile(profile),
    tools: enabledTools(defaults, profile),
    toolSettings
  };
}

export function applyRunMode(config: ScanConfig, runMode: RunMode): ScanConfig {
  const osintEnabled = runMode === "osint_only" || runMode === "normal_scan_plus_osint";
  return {
    ...config,
    runMode,
    osintEnabled,
    osintProfile: "safe_mvp",
    toolSettings: {
      ...config.toolSettings,
      osint: {
        ...config.toolSettings.osint,
        enabled: osintEnabled,
        mode: "safe_mvp",
        passiveOnly: true,
        leakSources: {
          ...config.toolSettings.osint.leakSources,
          metadataFeed: normalizeMetadataFeed(config.toolSettings.osint.leakSources?.metadataFeed)
        },
        darkweb: {
          enabled: config.toolSettings.osint.darkweb?.enabled ?? true,
          manualMetadataImport: {
            enabled: config.toolSettings.osint.darkweb?.manualMetadataImport?.enabled ?? false,
            sourceName: config.toolSettings.osint.darkweb?.manualMetadataImport?.sourceName ?? "",
            filePath: config.toolSettings.osint.darkweb?.manualMetadataImport?.filePath ?? "",
            maxResults: config.toolSettings.osint.darkweb?.manualMetadataImport?.maxResults ?? 25
          },
          customHttpsProvider: {
            enabled: config.toolSettings.osint.darkweb?.customHttpsProvider?.enabled ?? false,
            providerUrl: config.toolSettings.osint.darkweb?.customHttpsProvider?.providerUrl ?? "",
            apiKeyEnv: config.toolSettings.osint.darkweb?.customHttpsProvider?.apiKeyEnv || "DARKWEB_METADATA_TOKEN",
            apiKeyConfigured: Boolean(config.toolSettings.osint.darkweb?.customHttpsProvider?.apiKeyConfigured),
            maxResults: config.toolSettings.osint.darkweb?.customHttpsProvider?.maxResults ?? 25,
            timeout: config.toolSettings.osint.darkweb?.customHttpsProvider?.timeout ?? 10
          }
        }
      }
    }
  };
}

export function configFromDefaults(defaults: ConfigDefaults): ScanConfig {
  const scanProfile = defaults.scanProfile === "custom" ? "balanced" : defaults.scanProfile;
  const toolSettings = toolSettingsForProfile(defaults, scanProfile);
  return {
    target: "",
    wordlist: defaults.wordlist,
    trafficProfile: trafficFromScanProfile(scanProfile),
    scanProfile,
    runMode: "normal_scan_only",
    osintEnabled: false,
    osintProfile: "safe_mvp",
    reportDepth: defaults.reportDepth,
    tools: enabledTools(defaults, scanProfile),
    toolSettings,
    detailedNmapEnabled: false,
    ai: normalizeAiConfig(defaults.ai || defaultAiConfig)
  };
}

export function normalizeScanConfig(config: ScanConfig, defaults: ConfigDefaults): ScanConfig {
  const fallback = configFromDefaults(defaults);
  const incomingToolSettings = config.toolSettings || fallback.toolSettings;
  const incomingOsint = incomingToolSettings.osint || fallback.toolSettings.osint;
  return {
    ...fallback,
    ...config,
    target: stringValue(config.target, fallback.target),
    wordlist: stringValue(config.wordlist, fallback.wordlist),
    trafficProfile: ["safe", "balanced", "fast"].includes(String(config.trafficProfile)) ? config.trafficProfile : fallback.trafficProfile,
    scanProfile: ["fast", "balanced", "slow", "custom"].includes(String(config.scanProfile)) ? config.scanProfile : fallback.scanProfile,
    runMode: ["normal_scan_only", "osint_only", "normal_scan_plus_osint"].includes(String(config.runMode)) ? config.runMode : fallback.runMode,
    osintEnabled: boolValue(config.osintEnabled, fallback.osintEnabled),
    osintProfile: "safe_mvp",
    reportDepth: ["summary", "balanced", "deep"].includes(String(config.reportDepth)) ? config.reportDepth : fallback.reportDepth,
    tools: { ...fallback.tools, ...(config.tools || {}) },
    toolSettings: {
      ...fallback.toolSettings,
      ...incomingToolSettings,
      katana: { ...fallback.toolSettings.katana, ...(incomingToolSettings.katana || {}) },
      gobuster: { ...fallback.toolSettings.gobuster, ...(incomingToolSettings.gobuster || {}) },
      ffuf: { ...fallback.toolSettings.ffuf, ...(incomingToolSettings.ffuf || {}) },
      checks: { ...fallback.toolSettings.checks, ...(incomingToolSettings.checks || {}) },
      screenshots: { ...fallback.toolSettings.screenshots, ...(incomingToolSettings.screenshots || {}) },
      nuclei: { ...fallback.toolSettings.nuclei, ...(incomingToolSettings.nuclei || {}) },
      ipNmap: { ...fallback.toolSettings.ipNmap, ...(incomingToolSettings.ipNmap || {}) },
      osint: {
        ...fallback.toolSettings.osint,
        ...incomingOsint,
        mode: "safe_mvp",
        passiveOnly: true,
        sources: {
          ...fallback.toolSettings.osint.sources,
          ...(incomingOsint.sources || {}),
          githubCodeSearch: {
            ...fallback.toolSettings.osint.sources.githubCodeSearch,
            ...(incomingOsint.sources?.githubCodeSearch || {})
          },
          wayback: {
            ...fallback.toolSettings.osint.sources.wayback,
            ...(incomingOsint.sources?.wayback || {})
          },
          crtsh: {
            ...fallback.toolSettings.osint.sources.crtsh,
            ...(incomingOsint.sources?.crtsh || {})
          },
          knownBreachCatalog: {
            ...fallback.toolSettings.osint.sources.knownBreachCatalog,
            ...(incomingOsint.sources?.knownBreachCatalog || {})
          }
        },
        leakSources: {
          ...fallback.toolSettings.osint.leakSources,
          ...(incomingOsint.leakSources || {}),
          metadataFeed: normalizeMetadataFeed(incomingOsint.leakSources?.metadataFeed)
        },
        darkweb: {
          ...fallback.toolSettings.osint.darkweb,
          ...(incomingOsint.darkweb || {}),
          manualMetadataImport: {
            ...fallback.toolSettings.osint.darkweb.manualMetadataImport,
            ...(incomingOsint.darkweb?.manualMetadataImport || {})
          },
          customHttpsProvider: {
            ...fallback.toolSettings.osint.darkweb.customHttpsProvider,
            ...(incomingOsint.darkweb?.customHttpsProvider || {})
          }
        }
      }
    },
    detailedNmapEnabled: boolValue(config.detailedNmapEnabled, fallback.detailedNmapEnabled || false),
    ai: normalizeAiConfig(config.ai)
  };
}

export function markCustom(config: ScanConfig): ScanConfig {
  return { ...config, scanProfile: "custom" };
}
