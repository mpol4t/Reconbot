import type { ToolSettings } from "./api";

export type MetadataFeedProviderId = "local_demo_feed" | "custom_https_metadata_feed" | "future_trusted_provider_profile";
export type MetadataFeedSourceType = "local_file" | "https_json" | "";

export interface MetadataFeedBackendConfig {
  enabled: boolean;
  providerId: string;
  sourceName: string;
  sourceType: MetadataFeedSourceType;
  feedPath: string;
  feedUrl: string;
  apiKeyEnv: string;
  timeout: number;
  maxResults: number;
}

export interface MetadataFeedValidation {
  warnings: string[];
  errors: string[];
}

export const METADATA_FEED_PROVIDERS: Array<{ id: MetadataFeedProviderId; label: string; description: string }> = [
  { id: "custom_https_metadata_feed", label: "Custom HTTPS metadata feed", description: "Güvenilir metadata-only HTTPS JSON endpoint." },
  { id: "local_demo_feed", label: "Local demo metadata feed", description: "Demo fixture sadece yerel test içindir." },
  { id: "future_trusted_provider_profile", label: "Future trusted provider profile / yakında", description: "Placeholder. Canlı provider entegrasyonu henüz uygulanmadı." }
];

export const LOCAL_EXAMPLE_METADATA_FEED: ToolSettings["osint"]["leakSources"]["metadataFeed"] = {
  enabled: true,
  providerId: "local_demo_feed",
  sourceName: "local_test_metadata_feed",
  sourceType: "local_file",
  feedPath: "docs/examples/leak_metadata_feed.sample.json",
  feedUrl: "",
  apiKeyEnv: "",
  timeout: 10,
  maxResults: 25
};

export const DEFAULT_METADATA_FEED: ToolSettings["osint"]["leakSources"]["metadataFeed"] = {
  enabled: false,
  providerId: "custom_https_metadata_feed",
  sourceName: "",
  sourceType: "https_json",
  feedPath: "",
  feedUrl: "",
  apiKeyEnv: "",
  timeout: 10,
  maxResults: 25
};

export function metadataFeedProviderId(
  feed: Partial<ToolSettings["osint"]["leakSources"]["metadataFeed"]> | undefined
): MetadataFeedProviderId {
  if (feed?.providerId === "local_demo_feed") return "local_demo_feed";
  if (feed?.providerId === "future_trusted_provider_profile") return "future_trusted_provider_profile";
  if (feed?.providerId === "custom_https_metadata_feed") return "custom_https_metadata_feed";
  if (feed?.feedPath?.trim() && !feed?.feedUrl?.trim()) return "local_demo_feed";
  return "custom_https_metadata_feed";
}

export function metadataFeedSourceType(
  feed: Partial<ToolSettings["osint"]["leakSources"]["metadataFeed"]> | undefined
): MetadataFeedSourceType {
  const providerId = metadataFeedProviderId(feed);
  if (providerId === "future_trusted_provider_profile") return "";
  if (providerId === "local_demo_feed") return "local_file";
  if (providerId === "custom_https_metadata_feed") return "https_json";
  if (feed?.sourceType === "https_json") return "https_json";
  if (feed?.sourceType === "local_json" || feed?.sourceType === "local_file") return "local_file";
  if (feed?.feedUrl?.trim()) return "https_json";
  if (feed?.feedPath?.trim()) return "local_file";
  return "https_json";
}

export function normalizeMetadataFeed(
  feed: Partial<ToolSettings["osint"]["leakSources"]["metadataFeed"]> | undefined
): ToolSettings["osint"]["leakSources"]["metadataFeed"] {
  const providerId = metadataFeedProviderId(feed);
  const sourceType = metadataFeedSourceType({ ...feed, providerId });
  return {
    ...DEFAULT_METADATA_FEED,
    ...(feed || {}),
    providerId,
    enabled: Boolean(feed?.enabled),
    timeout: Number.isFinite(feed?.timeout) ? Number(feed?.timeout) : DEFAULT_METADATA_FEED.timeout,
    maxResults: Number.isFinite(feed?.maxResults) ? Number(feed?.maxResults) : DEFAULT_METADATA_FEED.maxResults,
    sourceType
  };
}

export function metadataFeedBackendConfig(
  feed: Partial<ToolSettings["osint"]["leakSources"]["metadataFeed"]> | undefined
): MetadataFeedBackendConfig {
  const normalized = normalizeMetadataFeed(feed);
  const sourceType = metadataFeedSourceType(normalized);
  return {
    enabled: normalized.enabled,
    providerId: normalized.providerId,
    sourceName: normalized.sourceName,
    sourceType: sourceType,
    feedPath: normalized.providerId === "local_demo_feed" && sourceType === "local_file" ? normalized.feedPath : "",
    feedUrl: normalized.providerId === "custom_https_metadata_feed" && sourceType === "https_json" ? normalized.feedUrl : "",
    apiKeyEnv: normalized.apiKeyEnv,
    timeout: normalized.timeout,
    maxResults: normalized.maxResults
  };
}

export function validateMetadataFeedUiConfig(
  feed: Partial<ToolSettings["osint"]["leakSources"]["metadataFeed"]> | undefined
): MetadataFeedValidation {
  const normalized = normalizeMetadataFeed(feed);
  const sourceType = metadataFeedSourceType(normalized);
  const warnings: string[] = [];
  const errors: string[] = [];
  const feedPath = normalized.feedPath.trim();
  const feedUrl = normalized.feedUrl.trim();

  if (!normalized.enabled) return { warnings, errors };

  if (normalized.providerId === "future_trusted_provider_profile") {
    errors.push("Future trusted provider profile yakında; etkin durumdayken scan başlatılamaz.");
    return { warnings, errors };
  }

  if (normalized.providerId === "local_demo_feed" && !feedPath) {
    errors.push("Local demo metadata feed açık ama local JSON dosya yolu yapılandırılmamış.");
  }
  if (normalized.providerId === "custom_https_metadata_feed" && !feedUrl) {
    errors.push("Custom HTTPS metadata feed açık ama HTTPS JSON endpoint yapılandırılmamış.");
  }
  if (sourceType === "https_json" && feedUrl.toLowerCase().startsWith("file://")) {
    errors.push("file:// URL kabul edilmez. Local JSON dosya yolu modunu kullan.");
  } else if (sourceType === "https_json" && feedUrl && !feedUrl.toLowerCase().startsWith("https://")) {
    errors.push("Yalnızca https:// endpoint kabul edilir.");
  }

  return { warnings, errors };
}

export function metadataFeedStatusPreview(
  feed: Partial<ToolSettings["osint"]["leakSources"]["metadataFeed"]> | undefined
): string[] {
  const normalized = normalizeMetadataFeed(feed);
  const sourceType = metadataFeedSourceType(normalized);
  const feedPath = normalized.feedPath.trim();
  const feedUrl = normalized.feedUrl.trim();
  const messages: string[] = [];

  if (!normalized.enabled) {
    return ["Metadata feed sağlayıcısı kurulu ama kapalı. Yalnızca kapalı kaynak kapsamı olarak görünür."];
  }

  messages.push("Provider registry runtime öncesinde metadata-only feed kurallarını uygular.");

  if (normalized.providerId === "future_trusted_provider_profile") {
    messages.push("Future trusted provider profile yakında. Runtime provider entegrasyonu henüz uygulanmadı.");
  } else if (normalized.providerId === "local_demo_feed" && feedPath) {
    messages.push(`Metadata feed local JSON dosyasından okunacak: ${feedPath}`);
    messages.push("Demo fixture sadece yerel test içindir.");
  } else if (normalized.providerId === "custom_https_metadata_feed" && feedUrl.toLowerCase().startsWith("https://")) {
    messages.push("Metadata feed güvenilir HTTPS JSON metadata endpoint'ini isteyecek.");
    messages.push("Yalnızca https:// endpoint kabul edilir. Sadece güvenilir metadata-only provider kullan.");
  } else if (normalized.providerId === "custom_https_metadata_feed" && feedUrl.toLowerCase().startsWith("http://")) {
    messages.push("Yalnızca https:// endpoint kabul edilir.");
  } else if (normalized.providerId === "custom_https_metadata_feed" && feedUrl.toLowerCase().startsWith("file://")) {
    messages.push("file:// URL kabul edilmez. Local JSON dosya yolu modunu kullan.");
  } else {
    messages.push("Açık ama yapılandırılmamış. Collector not_configured döndürür.");
  }

  if (normalized.apiKeyEnv.trim()) {
    messages.push(`ReconBot API key değerini ${normalized.apiKeyEnv.trim()} ortam değişkeninden okur. Key değeri raporlarda veya run_result.json içinde saklanmaz.`);
  }

  return messages;
}
