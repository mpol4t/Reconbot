# Leak-Source Collector Contract

This package defines the leak-source collector contract and the live
metadata-only collectors:

- `public_breach_catalog`: adapter over the existing known-breach/HIBP-style
  public catalog flow.
- `metadata_feed`: generic configurable local-JSON or HTTPS-JSON breach/leak
  metadata feed adapter.
- `provider_registry`: safe provider profiles for metadata-only source
  selection before any file or network access.

ReconBot still does not perform Tor access, onion crawling, darkweb forum
scraping, credential validation, dump downloads, raw paste collection, or secret
collection. These collectors consume only public or trusted-provider metadata.

The higher-level `osint_core.darkweb` package wraps these safe results into the
top-level `osint.darkweb_intelligence` object and adds manual metadata import,
future trusted-provider placeholders, and an explicit unsupported Tor/onion
source row. `osint.leak_intelligence` remains for compatibility.

Visible HTML report and Settings copy is Turkish-first for operators. Raw
`run_result.json` keys, internal enum values, source IDs, provider IDs, file
paths, URLs, tool names, and protocol/product names remain unchanged. Status
translation is display-only in the report/UI, for example `disabled` ->
`Kapalı`, `no_match` -> `Eşleşme yok`, `completed` -> `Tamamlandı`, `timeout`
-> `Zaman aşımı`, and `auth_required` -> `Kimlik doğrulama gerekli`.
Dynamic breach/leak snippets, confidence reasons, scope caveats, recommended
actions, safety notes, manual lookup labels, provider messages, and common
breach data classes are translated in the visible HTML layer only. Summary and
Balanced report depth avoid showing raw English source/provider strings; Deep
and advanced diagnostics may still expose raw fields under technical/raw
sections for debugging.

## Allowed Metadata

- Public breach catalog metadata
- Public report URLs
- Breach names and breach dates
- Affected account counts
- Compromised data class names
- Redacted snippets
- Source availability and source-health status
- Browser-safe manual review links

## Hard Forbidden Data

ReconBot must never collect, store, log, or validate:

- Passwords or password hashes
- API keys, access tokens, refresh tokens, private keys, or session cookies
- Full database dumps
- Personal records from dumps or paste bodies
- Credential validation results
- Login attempts or account checks
- Bought/sold data
- Raw material from private forums requiring unauthorized access

If a provider returns sensitive material, the collector must suppress it
immediately, store only category and redaction marker metadata, increment
`suppressed_sensitive_items`, and attach a safety note.

## Result Shape

Collectors return `LeakSourceResult`:

- `source_name`
- `source_type`
- `status`
- `observed_references`
- `suppressed_sensitive_items`
- `source_health_row`
- `operator_notes`
- `risk_score_impact=0`

Each observed reference must be metadata-only and include scope provenance:

- `requested_target_host`
- `requested_registered_domain`
- `observed_on_host`
- `observed_on_registered_domain`
- `scope_origin`
- `applies_to_target`
- `applies_to_parent_org`
- `scope_caveat`

Public third-party breach references default to
`scope_origin=external_verified_source`, `applies_to_target=unknown`, and
`recommended_action=manual relevance review`.

When a public reference URL or provider host is known, external verified source
references must also populate `observed_on_host` and
`observed_on_registered_domain` with the source host. For the HIBP-style public
catalog adapter this is `haveibeenpwned.com`.

## Current And Future Source Classes

1. `public_breach_catalog`: live HIBP-style public breach catalog metadata
   adapter, no credentials, no raw dumps, no risk-score impact.
2. `leak_metadata_api`: metadata API, disabled unless configured, no raw secrets.
   The current implementation is the generic `metadata_feed` collector.
3. `paste_metadata`: title/url/date only unless content can be safely summarized.
4. `darkweb_index`: disabled by default, explicit opt-in only, metadata only.
5. `manual_review_source`: browser-safe suggestion only, not a finding.

## Provider Registry

Metadata feed source selection is constrained by provider profiles:

1. `local_demo_feed`
   - Display name: Local demo metadata feed
   - Source type: `leak_metadata_api`
   - Enabled by default: false
   - Allowed source modes: `local_file`
   - Auth mode: `none`
   - Schema adapter: `generic_metadata_feed_v1`
   - Operator warning: Demo fixture for local testing only. Do not treat as a production intelligence provider.
2. `custom_https_metadata_feed`
   - Display name: Custom HTTPS metadata feed
   - Source type: `leak_metadata_api`
   - Enabled by default: false
   - Allowed source modes: `https_json`
   - Allowed URL pattern: `https://`
   - Auth mode: `optional_bearer_env`
   - Schema adapter: `generic_metadata_feed_v1`
   - Operator warning: Only use trusted metadata-only feeds. Do not configure feeds containing credentials, dumps, raw paste content, or personal records.
3. `future_trusted_provider_profile`
   - Display name: Future trusted provider profile
   - Status: placeholder
   - No live provider integration is implemented.

All profiles are metadata-only, forbid raw content, credentials, and dumps, and
have `risk_score_impact=0`. Profiles cannot override these safety boundaries.
No live third-party provider URL is hardcoded.

Provider validation rules:

- Unknown `providerId` returns `invalid_config` before file/network access.
- `local_demo_feed` accepts only `sourceType=local_file` with `feedPath`.
- `custom_https_metadata_feed` accepts only `sourceType=https_json` with a
  complete `https://` `feedUrl`; `http://`, `file://`, malformed, and
  unsupported schemes are rejected before any request.
- `future_trusted_provider_profile` returns `not_implemented` and never runs.
- Existing configs without `providerId` still work: `feedPath` infers
  `local_demo_feed`, `feedUrl` infers `custom_https_metadata_feed`, and an old
  disabled or enabled-but-empty config keeps the disabled/not_configured
  behavior.

Runtime source-health rows include `provider_id`, `provider_display_name`,
`provider_status`, `source_mode`, `schema_adapter`, `metadata_only=true`,
`forbids_credentials=true`, `forbids_dumps=true`, `forbids_raw_content=true`,
`provider_validation_status`, `provider_validation_message`,
`items_loaded_count`, `items_matched_count`, `items_suppressed_count`,
`api_key_env_configured`, and `api_key_value_serialized=false`.

## Metadata Feed Collector

`metadata_feed.py` implements `source_name=leak_metadata_feed` by default and
`source_type=leak_metadata_api`. It is disabled unless explicitly configured
under OSINT settings:

```json
{
  "osint": {
    "leakSources": {
      "metadataFeed": {
        "enabled": false,
        "providerId": "custom_https_metadata_feed",
        "sourceName": "",
        "sourceType": "https_json",
        "feedPath": "",
        "feedUrl": "",
        "apiKeyEnv": "",
        "timeout": 10,
        "maxResults": 25
      }
    }
  }
}
```

Behavior:

- `enabled=false` returns a `disabled` source coverage row.
- `enabled=true` without `feedPath` or `feedUrl` returns `not_configured`.
- `providerId=local_demo_feed` with `sourceType=local_file` reads a local JSON
  feed for testing or trusted offline inputs.
- `providerId=custom_https_metadata_feed` with `sourceType=https_json` uses
  `feedUrl`, which must be a complete `https://` URL with a host; `http://`,
  `file://`, unsupported schemes, local filesystem URLs, and shell commands are
  not allowed. Invalid schemes are rejected before any network request is made.
- `apiKeyEnv` is the name of an environment variable to read at runtime. API key
  values are read only when an HTTPS feed is requested, sent as an
  `Authorization: Bearer ...` header, and never written to `run_result.json`,
  reports, logs, source health, or operator notes. If the environment variable
  is missing, the collector returns `auth_required` with a clear source-health
  message and does not make the feed request.
- No third-party URL is hardcoded or enabled by default.
- Electron operators configure the same object in Settings under
  **OSINT Enrichment → Darkweb / Sızıntı / İhlal Metadata Feed’i**. The UI keeps
  Fast/Balanced/Slow presets disabled by default, emits `providerId`, passes
  only the local `feedPath` string for local demo mode, validates HTTPS mode
  before scan start, and writes `sourceType=local_file` or `https_json` into
  `tool_settings.osint.leakSources.metadataFeed`.
- The development sample at `docs/examples/leak_metadata_feed.sample.json` is
  documentation/test data only. It is not enabled by default and uses only
  generic example-domain metadata.
- The development config at
  `docs/examples/osint_local_metadata_feed.config.yaml` explicitly enables that
  sample feed for a local `https://www.example.com` OSINT demonstration.
- The JSON development config at
  `docs/examples/osint_metadata_feed_demo_config.json` exercises the same path
  through the normal CLI/Electron config loader. This is the preferred
  copy-paste demo config because JSON is accepted by the YAML loader and keeps
  the example self-contained.

Local feed example with an existing ReconBot config file:

```yaml
reconbot:
  run_mode: osint_only
  osint:
    enabled: true
    profile: safe_mvp
    passiveOnly: true
    includeCertificateTransparency: false
    includeHistoricalUrls: false
    includePublicCodeReferences: false
    includeKnownBreachCatalog: true
    includeSearchDorkSuggestions: false
    leakSources:
      metadataFeed:
        enabled: true
        providerId: local_demo_feed
        sourceName: local_test_metadata_feed
        sourceType: local_file
        feedPath: docs/examples/leak_metadata_feed.sample.json
        feedUrl: ""
        apiKeyEnv: ""
        timeout: 10
        maxResults: 25
```

Run it with:

```sh
RECONBOT_SUPPRESS_REPORT_OPEN=1 python3 -m reconbot https://www.example.com -c docs/examples/osint_metadata_feed_demo_config.json
```

Electron UI smoke-test values:

```json
{
  "target": "www.example.com",
  "metadataFeed": {
    "enabled": true,
    "providerId": "local_demo_feed",
    "sourceName": "local_test_metadata_feed",
    "sourceType": "local_file",
    "feedPath": "docs/examples/leak_metadata_feed.sample.json",
    "feedUrl": "",
    "apiKeyEnv": "",
    "timeout": 10,
    "maxResults": 25
  }
}
```

In the UI this lives at Settings → OSINT Enrichment → Darkweb / Sızıntı / İhlal
Metadata Feed’i. The optional `Local örnek metadata feed’i yükle` helper fills
the same values and is labelled as a demo fixture for local testing only. Expected
runtime proof is `metadataFeed.enabled=true`, `provider_id=local_demo_feed`,
`provider_display_name=Local demo metadata feed`, `source_mode=local_file`,
`provider_validation_status=valid`, `enabled_collectors_count=2`,
`leak_metadata_feed.status=completed`, loaded/matched counts of `1`, suppressed
count `0`, observed references `1`, credential material collected `false`, raw
secret collected `false`, and risk score impact `none` / `0`.

Safety boundary for this smoke path: no Tor/onion crawling, no credentials,
no dumps, no secrets/raw leaked records, and no credential validation. No Tor crawling
is used. No credentials are collected or validated.

The local feed path is read as JSON only. ReconBot does not execute commands from
configuration, does not enable this sample automatically, and does not serialize
API key values when `apiKeyEnv` is used for an HTTPS provider.

When configured, `run_result.json.osint.leak_intelligence.source_health[]`
includes safe runtime diagnostics for the metadata feed:

- `collector_name=leak_metadata_feed`
- `provider_id`
- `provider_display_name`
- `provider_validation_status`
- `provider_validation_message`
- `source_mode`
- `feed_source_type=local_file` or `https_json`
- `feed_path_basename` for local files, never the full path in the diagnostic
  field
- `items_loaded_count`
- `items_matched_count`
- `items_suppressed_count`

Disabled and not-configured runs include explicit reasons:
`metadataFeed.enabled=false` or `enabled=true but no feedPath/feedUrl`. API key
environment variable names may appear in sanitized settings as configured flags,
but API key values are never serialized.

Report behavior:

- Completed provider rows show provider ID/display name in source coverage and
  observed reference details.
- `invalid_config`, `not_implemented`, `not_configured`, and `disabled` remain
  source coverage only and do not create findings.
- Metadata references are not active vulnerability findings and do not affect
  the risk score.

Runtime/report status mapping:

- `disabled`: metadata feed is installed but `metadataFeed.enabled=false`; no
  findings or references are emitted. Visible report text:
  `Metadata feed sağlayıcısı kurulu ama kapalı.`
- `not_configured`: metadata feed is enabled but no local `feedPath` or HTTPS
  `feedUrl` is configured; no finding is emitted, and source coverage explains
  the missing setting. Visible report text:
  `Metadata feed açık ama feedPath/feedUrl yapılandırılmamış.`
- `completed`: the feed was read successfully. Matching rows are rendered as
  metadata-only references with the report note `Metadata feed sonucu. Bu aktif
  bir zafiyet bulgusu değildir.`
- `no_match`: the feed was read successfully but no item matched the target
  host, registered domain, or strong organization aliases.

Report wording intentionally separates active OSINT exposure evidence from
metadata-only leak/breach references. A run can show `Gözlemlenmiş aktif OSINT
kanıtı: 0` and `Sadece-metadata sızıntı/ihlal referansı: 1`; that means a public
metadata reference was observed, not that ReconBot found an active vulnerability
or collected leaked material. The report states `Kurumla gerçekten ilişkili olup
olmadığını manuel doğrula; kimlik bilgisi toplama.` and risk score impact
remains none.

The Turkish report explicitly separates:

- `Kanıt`: doğrulanmış public kaynakta gözlemlenen ve linki kontrol edilebilir veri.
- `Bağlam`: parent organization, affiliate, altyapı veya kaynak kapsamı bilgisi.
- `Manuel Öneri`: Google dork, Shodan/Censys/urlscan/Maps gibi operatörün manuel bakacağı öneriler; risk skoruna etki etmez.
- `Kapalı / Yapılandırılmamış`: modül var ama bu çalıştırmada açık değil veya gerekli ayar girilmemiş.

Safe feed schema:

```json
{
  "source_name": "example_metadata_feed",
  "generated_at": "2026-06-23T00:00:00Z",
  "items": [
    {
      "title": "Example breach reference",
      "reference_url": "https://example.com/report/example",
      "published_at": "2026-05-01",
      "breach_date": "2026-04-01",
      "affected_accounts": 12345,
      "data_classes": ["Email addresses", "Names"],
      "matched_domains": ["example.com"],
      "matched_brands": ["Example"],
      "snippet": "Metadata-only public report mention.",
      "source_provider": "example_provider"
    }
  ]
}
```

Provider variants are normalized for `data_classes` /
`compromised_data_classes`, `published_at` / `added_date`, `reference_url` /
`url`, `matched_domains` / `domains`, and `matched_brands` / `brands`.

Matching is conservative. Exact target-host and registered-domain metadata
matches receive high confidence. Brand and keyword alias matches require strong
non-generic aliases and remain manual-review metadata references. Weak
substring, TLD-only, `www`, and short organization aliases do not create
observed references.

## Output Contract

`run_result.json.osint.leak_intelligence` contains:

- `enabled`
- `status`
- `live_collection_performed`
- `enabled_collectors_count`
- `summary.observed_references`
- `summary.suppressed_sensitive_items`
- `summary.credential_material_collected=false`
- `summary.raw_secret_collected=false`
- `summary.risk_score_impact=none`
- `results[]`
- `source_health[]`

The existing `osint.signals[]` `known_breach_reference` row remains for
backward compatibility. The same public catalog reference is now primarily
reported under `Darkweb / Sızıntı / İhlal İstihbaratı`. Metadata-feed references
are also reported there and grouped with other metadata-only breach/leak
references. The report section is always visible and states that current leak
intelligence is metadata-only, Tor/onion crawling is not enabled, no darkweb
forum scraping exists, and no credentials, dumps, secrets, or raw leaked records
are collected.

Provider registry rows are Turkish-readable in HTML (`Sağlayıcı`, `Provider ID`,
`Kaynak`, `Kaynak modu`, `Durum`, `Güvenlik sözleşmesi`, `Kayıtlar`, `Kullanıcı
mesajı`). The security contract is shown as one operator-readable cell:
`Metadata-only; kimlik bilgisi, dump ve ham içerik yasak.` Raw provider IDs,
source IDs, and detailed booleans stay unchanged in JSON/advanced diagnostics.

Disabled, not-configured, no-match, timeout, authentication, and provider-error
metadata-feed states appear in source coverage only. They are not rendered as
findings. Matching metadata-feed references are still public breach/leak metadata
references, not active vulnerability findings, and always require manual
organization relevance review.

## Meaning Of Result Types

- Active vulnerability finding: scanner or validation evidence that may affect
  risk scoring. Leak-source metadata is not this.
- Public breach/leak metadata reference: third-party public catalog metadata
  such as breach name, public report URL, breach date, affected account count,
  and data classes. It has `risk_score_impact=0`.
- Manual review task: an operator follow-up to validate organization relevance
  without collecting credentials, dumps, secrets, or personal records.

Future providers must plug into this same contract. They should normalize to
`LeakSourceResult`, run `sanitize_reference_payload`, suppress sensitive values
as categories only, emit source-health rows, and preserve
`risk_score_impact=0` unless a future policy explicitly defines a separate
validated exposure rule. Adding a provider must not add Tor, onion crawling,
darkweb forum scraping, credential validation, raw dump collection, or secret
storage.

## Source Health

Collectors must emit source-health rows with:

- `source`
- `endpoint` or `provider`
- `status`
- `source_status`
- `latency_ms`
- `error`
- `error_class`
- `user_message`
- `browser_safe`
- `render_as_clickable=false` for APIs
- `risk_score_impact=0`

Manual links use `status=suggestion_only` and
`source_status=suggestions_generated`; they are not counted as attempted live
sources unless a real provider request was made.
