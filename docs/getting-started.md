# Getting started

## Install the beta

Get the package matching your platform from the [release](https://github.com/mpol4t/Reconbot/releases/tag/v0.1.0-beta.1). Compare its SHA-256 with the release's `SHA256SUMS.txt` if needed.

### macOS Apple Silicon

Open the DMG and drag ReconBot into Applications. Quit an older instance before replacing it. Keep the application-support workspace to retain settings/history. The beta is unsigned and not notarized; macOS may require explicit permission to open it through System Settings → Privacy & Security. Do not disable system-wide security protections.

### Linux x86_64 and ARM64

Run `uname -m` and select the matching package:

| Output | DEB | AppImage |
| --- | --- | --- |
| `x86_64` | `ReconBot-0.1.0-linux-amd64.deb` | `ReconBot-0.1.0-linux-x86_64.AppImage` |
| `aarch64` / `arm64` | `ReconBot-0.1.0-linux-arm64.deb` | `ReconBot-0.1.0-linux-arm64.AppImage` |

On Debian/Ubuntu/Kali, install the matching DEB using the package manager. For an ARM64 VM:

```bash
sudo apt install ./ReconBot-0.1.0-linux-arm64.deb
```

Launch ReconBot from the application menu. For the AppImage, substitute your architecture's filename:

```bash
chmod +x ReconBot-0.1.0-linux-arm64.AppImage
./ReconBot-0.1.0-linux-arm64.AppImage
```

AppImage may require FUSE. Where supported, `--appimage-extract-and-run` is an alternative. Native Debian 12 container checks cover both architectures under Xvfb; this does not establish compatibility with every distribution, older glibc releases or 32-bit Linux. Intel macOS and Windows are not packaged in this beta. A macOS ARM64 installer cannot run on Linux ARM64.

## External tools

The application includes its Python backend. Install the scanner tools you enable separately: Nmap, Subfinder, DNSX, HTTPX, Katana, Gobuster, FFUF, Nuclei, WhatWeb and WAFW00F. SQLmap is needed only for Validation. Wordlists, browser runtime for screenshots and a local model/server for optional AI are separate prerequisites. Ensure the executable names resolve to the intended security tools; unrelated programs can share names such as `httpx`.

ReconBot checks selected dependencies before scanning. Disable tools you do not intend to run; a disabled tool is not a failed scan stage.

## First run

1. Open Configure and enter a complete authorized URL, domain or IP.
2. Select relevant tools and limits. Browse to a discovery wordlist where required.
3. Choose Save and lock to reuse a path across restarts; unlock it to change the list.
4. Start the scan and follow the Dashboard/Terminal.
5. Review Report/Findings/Threat Pipeline. The selected run owns its artifacts and independent jobs.

The interface defaults to English; choose Türkçe in the sidebar. Report explanations currently use Turkish. New report writes do not automatically reset the embedded report's reading position; Reload updates it explicitly.

## Validation and authentication

Select the originating scan before starting a job. Its host/port scope must match the submitted URL. SQLmap tests one GET/fixed POST parameter and stores separate evidence. Authentication supports HTTP Basic and fixed POST forms. Form field names are HTML `name` values, and required submit-button values may need to be supplied as extra fields.

Automatic form comparison needs no success text. A repeatable changed response is a candidate requiring manual login verification. It is not accepted credentials. Dynamic CSRF, JavaScript, MFA and SSO flows are unsupported. Limits, cancellation and rate/lockout stops apply; the baseline scan score remains unchanged.

Use [four local test sites](testing.md) before a real assessment. [Türkçe rehber](first-use-tr.md) explains the same workflow in Turkish.

## Optional AI

Load a model in an OpenAI-compatible local server. Set its endpoint/model in Settings → Operator Copilot and test the connection. AI is experimental; tested models produced incorrect technical explanations. Review original evidence rather than treating a model reply as proof. See [AI details](ai-operator-copilot.md).
