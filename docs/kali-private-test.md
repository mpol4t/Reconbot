# Test the private beta on Kali Linux

The repository and release remain private during operator acceptance. Sign into GitHub as the repository owner or an explicitly invited collaborator; anonymous release download links will not work.

## 1. Check architecture

```bash
uname -m
```

Linux installers cover **x86_64/amd64** and **aarch64/arm64**. Choose `linux-amd64.deb` for `x86_64`, or `linux-arm64.deb` for `aarch64`/`arm64`. Do not mix architectures. The Mac Apple Silicon installer is a macOS application, not a Linux ARM64 package.

## 2. Download and install

In the VM browser, sign into GitHub, open the private Reconbot repository's Releases page and download the matching Linux DEB and `SHA256SUMS.txt`. The source ZIP is available separately.

For your **aarch64 VM**, from the download folder (x86_64 users substitute `amd64`):

```bash
sha256sum ReconBot-0.1.0-linux-arm64.deb
# Compare the output with that filename's entry in SHA256SUMS.txt.
sudo apt install ./ReconBot-0.1.0-linux-arm64.deb
```

Launch ReconBot from the application menu. If using the AppImage instead, make it executable and launch it as described in [getting started](getting-started.md). Kali installation is a pending operator check; native Linux package checks used Debian 12 on x86_64 and ARM64 under Xvfb.

The UI and Python backend are bundled. External scanners, SQLmap, lists, screenshot browser runtime and a local AI server are separate prerequisites. Enable only installed tools. Scanning and reporting must work with AI off.

## 3. Prepare the local test sites

To run the synthetic fixtures, download the release source ZIP and extract it. From its `Reconbot` folder:

```bash
python3 -m venv .lab-venv
.lab-venv/bin/python -m pip install requests urllib3 PyYAML dnspython tldextract
.lab-venv/bin/python desktop/scripts/release-labs.py
```

Run ReconBot against `http://127.0.0.1:8085` through `http://127.0.0.1:8088` **inside the same Kali VM**. VM localhost is different from the Mac's localhost. Follow the [test scenarios and expected outcomes](testing.md), including SQL positive/negative, Basic accepted credentials and form automatic candidates. These fixtures bind only to loopback. Stop the lab terminal with Ctrl+C when finished.

## 4. Acceptance checklist

- Install and start from the application menu without Node/npm or a Python installation for the app itself.
- Scan a local fixture with the selected installed tools; retain tool/status errors instead of treating them as clean results.
- Read the report while results update; verify the reading position survives.
- Inspect the graph's grouped URLs, clear selection and check physical zoom behavior.
- Test independent SQL validation and Basic/form authentication; preserve baseline score and show success/candidates first.
- Save a wordlist path, quit the app and reopen; confirm history and the lock remain.
- Missing/offline AI must leave scanning/reporting available. Optional AI explanations remain experimental.

If a step fails, record the app version, architecture, exact error and a screenshot using synthetic test data. Keep the repository private until these operator checks are reviewed. LinkedIn publication follows the public release, not this private testing stage.
