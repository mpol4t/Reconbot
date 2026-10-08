# Darkweb Intelligence

ReconBot darkweb intelligence is metadata-only.

- No Tor/onion crawling is implemented or supported.
- No forum, marketplace, paste, Telegram, Discord, or login-required breach scraping is performed.
- No credentials, passwords, hashes, tokens, private keys, cookies, raw dumps, or raw leaked records are collected.
- No credential validation is performed.
- Metadata references never increase risk score and are not active vulnerability findings.

The module aggregates existing safe leak intelligence (`known_breach_catalog` and the default-disabled metadata feed), optional local manual metadata JSON import, and provider profile placeholders for future trusted metadata-only sources.

Manual metadata import accepts only safe JSON metadata. It suppresses records with credential pairs, passwords, hashes, tokens, private keys, session cookies, JWT-like blobs, long hash/dump rows, multiline CSV-like leaked records, or raw paste/dump content. Suppressed raw values are never serialized.

Custom HTTPS provider support is a registry placeholder only. `https://` configuration can be validated, but no live third-party provider URL is hardcoded and no provider adapter runs in this finalization pass.
