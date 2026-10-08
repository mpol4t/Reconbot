# ReconBot desktop

Electron + React + TypeScript interface for ReconBot's Python scanner/report backend. The standalone installers contain a frozen backend; end users do not need npm or a separate Python installation. External scanner tools, SQLmap, wordlists, browser runtime and optional AI models remain separate.

See [getting started](../docs/getting-started.md), [test evidence](../docs/testing.md) and [architecture](../docs/architecture.md).

## Develop

Use Node.js 22.12+ and Python 3.11+. From the repository root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cd desktop
npm ci
npm run rebuild:pty
npm run dev
```

`node-pty` is native; macOS development may require Xcode Command Line Tools. Rebuild it after Electron upgrades. Development launches Electron's development bundle; the packaged app uses the ReconBot name/icon and preserves the original application storage ID.

## Checks

From `desktop/`:

```bash
npm run typecheck
npm run test:unit
npm run test:e2e
```

See [CONTRIBUTING](../CONTRIBUTING.md). Optional live-model and external-tool tests are separate. The manual installer workflow uploads build artifacts without publishing a release; remote CI is not claimed to have run before publication.

## Build installers

Build the frozen backend on the target OS/architecture. From `desktop/`, with the project virtual environment installed:

```bash
../.venv/bin/python -m pip install 'pyinstaller>=6.22,<7'
npm run package:mac
# On Linux:
npm run package:linux
```

To reproduce Linux x64 builds on a Mac, from the repository root:

```bash
docker build --platform linux/amd64 -f desktop/scripts/Dockerfile.linux -t reconbot-linux-builder:local .
docker run --rm --platform linux/amd64 \
  -v "$PWD:/source:ro" \
  -v "$PWD/desktop/build/linux:/package" \
  reconbot-linux-builder:local
```

Local Mac artifacts are in `desktop/dist/`; container Linux artifacts are in `desktop/build/linux/dist/`. Mac packages are unsigned/not notarized; Linux testing used Debian 12 under Xvfb.

Native checks: `package-smoke.cjs`, `package-graph-smoke.cjs`, `package-sqlmap-smoke.cjs` and `package-authentication-smoke.cjs`. SQL checks need an installed SQLmap; authentication checks use owned loopback fixtures. These scripts isolate app state from the user's installed workspace.

## Behavior

The main process owns scans, independent validation jobs and artifact access; the renderer uses restricted typed IPC. Reports are served through a validated local protocol. Embedded report reload is explicit. UI language defaults to English and includes Turkish; generated report explanations currently use Turkish.

Threat Pipeline groups discovery URLs by default and exposes complete recorded addresses in the inspector. Click a node again, blank canvas, Escape or Reset to clear selection. Touchpad sensitivity is adjustable.

Authentication supports HTTP Basic and fixed POST forms. Automatic form response comparison is a candidate mechanism, not proof of accepted credentials. SQL/auth jobs preserve the baseline scan score and selected-target ownership.

AI is optional and experimental. It uses the configured local model/server; it does not execute commands or perform live CVE lookup. Real local conversations failed technical semantic acceptance. Values/final answers are not secret-masked. Current details: [AI Operator Copilot](../docs/ai-operator-copilot.md).

## Local OSINT metadata-feed example

For synthetic testing, choose `www.example.com` and open Settings → OSINT Enrichment → **Darkweb / Sızıntı / İhlal Metadata Feed’i**. The local example emits:

```json
{
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
```

This is a local metadata fixture, not a live leak provider. No Tor/onion crawling is supported. No credentials or raw dumps are collected by this metadata-feed path, and no credential validation is performed. The separate Authentication module tests explicitly selected login endpoints; it is not part of OSINT metadata collection.

## License packaging

Original code is GPL-3.0-only; author copyright is in [COPYRIGHT](../COPYRIGHT). `package:mac`/`package:linux` generate actual installed dependency notices before packaging. `build/licenses/` becomes the installer's `resources/licenses/`. Supply the release source ZIP and build instructions alongside binaries. The Docker build generates its own Linux/CPython inventory; third-party license terms are preserved.
