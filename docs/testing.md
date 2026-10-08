# Testing and verification

## Recorded local results — 8 October 2026

| Area | Evidence |
| --- | --- |
| Python | 533 tests and 69 subtests passed on the final local suite. |
| Desktop | 43 unit tests; TypeScript and production builds passed. |
| Electron UI | Broad run: 49 passed, 2 optional live tests skipped, 1 Settings failure. The focus regression was fixed; all 12 Settings tests then passed. |
| Native macOS / Linux | Packaged app, bundled backend, offline report, navigation, graph, SQL and authentication checks passed. Linux used Debian 12 x86_64/Xvfb. |
| Real local tools | Four profiles with Katana/Gobuster/FFUF; four explicitly selected stock Nuclei templates; SQL positive/negative and nine authentication scenarios. 24 checks plus completion record. |
| Local AI | Real natural conversations exposed wrong CVE identity and verification advice. Mistral/Qwen semantic acceptance failed. Qwen also exceeded the live harness wait in one run. |

A startup-dependent stdout-timeout regression failed once under concurrent model/build load. Its test now allows two seconds for interpreter startup while the child still sleeps 60 seconds; output retention and process-registry assertions remain. All 42 related checks and the full suite then passed. An earlier Linux build smoke timeout was not reproduced by a stable sequential rebuild. These are local results; no GitHub CI result is claimed before the workflow runs.

Native macOS packaging was tested on Apple Silicon. Packages are unsigned/not notarized. Physical Linux installation, other distributions and the operator's final touchpad/install workflow remain open checks. Scanner matches and automatic login candidates still require verification.

## Reproduce automated checks

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

Live model tests are opt-in (`RECONBOT_RUN_LIVE_LM=1`) and need a loaded compatible server. They record real provider messages/answers for manual semantic review. Transport and raw/display parity alone are not semantic acceptance. Do not run them with private artifacts when generating public examples.

## Four local sites

Start the synthetic loopback-only labs from the repository root:

```bash
.venv/bin/python desktop/scripts/release-labs.py
```

| Target | Purpose |
| --- | --- |
| `http://127.0.0.1:8085` | Protected SQL controls, real 404s and no intentional exposure routes. |
| `http://127.0.0.1:8086` | Synthetic Git/backup exposure. |
| `http://127.0.0.1:8087` | Synthetic environment/debug/admin exposures. |
| `http://127.0.0.1:8088` | SQL and HTTP Basic/form authentication. |

Lists are generated in `desktop/build/release-labs/`. Use `discovery.txt` for discovery and `passwords.txt` for a short authentication example. Match the scan's host/port exactly; do not alternate between localhost and 127.0.0.1.

### SQLmap

Select a scan of `http://127.0.0.1:8088`. In Validation, use GET URL `http://127.0.0.1:8088/item?id=1`, parameter `id`. Compare with protected control `http://127.0.0.1:8088/clean?id=1`. A detected injection does not mean the database was dumped. Exercise Stop and inspect the separate evidence report.

### Authentication

The synthetic account is **operator / reconbot-demo-2026**. Use the generated short list.

- Basic: `http://127.0.0.1:8088/basic`, HTTP Basic, single username `operator`.
- Form: `http://127.0.0.1:8088/login`, POST, field names `username` / `password`, extra fields empty. Automatic response comparison should produce a candidate; verify it in the browser.
- Explicit form criterion: response contains `Welcome operator`; failure text `Invalid credentials`.
- Negative list: `passwords-negative.txt`. Do not treat no candidate as universal proof of secure authentication.

Success/candidate evidence should appear first; other attempts belong in the collapsed, paginated section. A 405/404/reference error before list execution should show that no list pairs were tested. The tool also stops on configured limits, lockout/rate responses and ambiguous results.

### Finish

Check small-window form access, report reading during updates, graph selection clearing, physical touchpad zoom and saved history/wordlists after restart. Stop the owned labs with Ctrl+C or:

```bash
.venv/bin/python desktop/scripts/release-labs.py --stop
```

The helper stops only its own four sites. Other servers and Docker containers are not reset. These local fixtures do not test public OSINT sources or every scanner/template. `desktop/scripts/release-labs-check.py` runs the installed-tool matrix against its own temporary loopback fixtures.
