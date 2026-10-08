import fs from "node:fs";
import path from "node:path";
import yaml from "js-yaml";
import type { ConfigDefaults, ReportDepth, ScanProfile, ToolDefault, TrafficProfile } from "../shared/api";
import { DEFAULT_AI_CONFIG } from "../shared/aiSettingsContract";

export const TOOL_ORDER: Array<[string, string]> = [
  ["nmap", "Nmap"],
  ["subfinder", "Subfinder"],
  ["dnsx", "DNSX"],
  ["httpx", "HTTPX"],
  ["katana", "Katana"],
  ["gobuster", "Gobuster"],
  ["ffuf", "FFUF"],
  ["historical_urls", "Historical URLs"],
  ["wafw00f", "WAFW00F"],
  ["whatweb", "WhatWeb"],
  ["checks", "Web Checks"],
  ["screenshots", "Screenshots"],
  ["nuclei", "Nuclei"]
];

const DEFAULT_ENABLED: Record<string, boolean> = {
  nmap: true,
  subfinder: true,
  dnsx: true,
  httpx: true,
  katana: true,
  gobuster: true,
  ffuf: false,
  historical_urls: false,
  wafw00f: true,
  whatweb: true,
  checks: true,
  screenshots: false,
  nuclei: true
};

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function asString(value: unknown, fallback: string): string {
  return typeof value === "string" && value.trim() ? value.trim() : fallback;
}

function asBool(value: unknown, fallback: boolean): boolean {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (["1", "true", "yes", "on"].includes(normalized)) return true;
    if (["0", "false", "no", "off"].includes(normalized)) return false;
  }
  return fallback;
}

function normalizeTrafficProfile(value: string): TrafficProfile {
  return value === "safe" || value === "fast" ? value : "balanced";
}

function normalizeScanProfile(value: string): ScanProfile {
  if (value === "fast" || value === "slow") return value;
  if (value === "safe") return "slow";
  return "balanced";
}

function normalizeReportDepth(value: string): ReportDepth {
  return value === "summary" || value === "deep" ? value : "balanced";
}

function toolField(name: string): string {
  return name === "screenshots" ? "screenshots_enable" : `${name}_enabled`;
}

function normalizeBaseOutput(repoRoot: string, rawOutputDir: string): string {
  const fallback = path.join(repoRoot, "reconbot", "output");
  const resolved = path.resolve(repoRoot, rawOutputDir || fallback);
  return path.basename(resolved).toLowerCase() === "latest" ? path.dirname(resolved) : resolved;
}

export function loadConfigDefaults(repoRoot: string): ConfigDefaults {
  const configPath = path.join(repoRoot, "config.yaml");
  let parsed: unknown = {};
  try {
    if (fs.existsSync(configPath)) {
      parsed = yaml.load(fs.readFileSync(configPath, "utf8"));
    }
  } catch {
    parsed = {};
  }

  const root = asRecord(parsed);
  const cfg = asRecord(root.reconbot ?? root);
  const report = asRecord(cfg.report);
  const traffic = asRecord(cfg.traffic);
  const screenshots = asRecord(cfg.screenshots);

  const tools: ToolDefault[] = TOOL_ORDER.map(([name, label]) => {
    const nested = asRecord(cfg[name]);
    const rawEnabled =
      cfg[toolField(name)] ??
      nested.enabled ??
      (name === "screenshots" ? screenshots.enabled : undefined);
    return {
      name,
      label,
      enabled: asBool(rawEnabled, DEFAULT_ENABLED[name] ?? true)
    };
  });

  return {
    repoRoot,
    wordlist: asString(cfg.wordlist, ""),
    outputDir: normalizeBaseOutput(repoRoot, asString(cfg.output_dir, "")),
    trafficProfile: normalizeTrafficProfile(asString(cfg.traffic_profile ?? traffic.profile, "balanced")),
    scanProfile: normalizeScanProfile(asString(cfg.scan_profile ?? cfg.traffic_profile ?? traffic.profile, "balanced")),
    reportDepth: normalizeReportDepth(asString(cfg.report_depth ?? report.depth, "balanced")),
    tools,
    ai: { ...DEFAULT_AI_CONFIG }
  };
}
