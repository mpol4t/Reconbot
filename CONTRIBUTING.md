# Contributing

This beta is a portfolio project with no promised support schedule. Focus reports and contributions on reproducible behavior rather than new tool requests.

## Set up

Follow the developer steps in [README](README.md). Keep tool versions, target scope and selected settings in your report. Use the [local labs](docs/testing.md) for repeatable examples. Do not attach live credentials or private scan output to public issues.

## Check a change

From the repository root:

```bash
.venv/bin/python -m pip install pytest pytest-subtests
.venv/bin/python -m pytest -q
```

From `desktop/`:

```bash
npm run typecheck
npm run test:unit
npm run test:e2e
```

Desktop E2E runs use the real Electron shell with isolated synthetic artifacts. Live model tests and real external-tool checks are separate and opt-in. Never treat a model transport test as semantic approval.

See [architecture](docs/architecture.md) before changing orchestration, selected-run ownership or evidence interpretation. Preserve raw values, cancellation, independent validation history and the distinction between completed, disabled and failed checks.

## Report a problem

Provide the OS/architecture, app version, steps, selected tool versions and expected versus observed result. A synthetic minimal example is preferred. For a possible product security issue, follow [SECURITY.md](SECURITY.md).

See [desktop/README.md](desktop/README.md) to build native packages. Do not commit environment files, model files, builds, test-user directories, reports, wordlists with real credentials or local resume state.

## Contribution license

Contributions to ReconBot original code are submitted under GPL-3.0-only. Preserve author/copyright notices, identify third-party code and retain its original terms; do not submit code you cannot license accordingly.
