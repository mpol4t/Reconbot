# Third-party components

GNU GPL version 3 only (`GPL-3.0-only`) at the repository root applies to ReconBot's original code. Dependencies and external tools retain their own copyright notices and license terms.

The desktop uses Electron/Chromium, React, xterm.js, node-pty, Cytoscape.js, d3-force, Lucide and associated tooling. Preserve the notices supplied by their installed packages and the Electron distribution when redistributing installers. The report's bundled Cytoscape license is in `reconbot/report/assets/cytoscape-LICENSE.txt`.

Python dependencies are declared in `pyproject.toml` and `requirements.txt`. PySide6 is used by the legacy Python desktop path and retains its Qt/PySide licensing terms; the frozen Electron backend excludes that optional GUI dependency. PyInstaller retains its own license and bootloader exception.

Nmap, ProjectDiscovery tools, Gobuster, FFUF, SQLmap, WhatWeb and WAFW00F are external prerequisites, not relicensed by ReconBot's GPL license and not included as scanner binaries in this beta. Model files and server software are also separate. Review their license terms if you distribute them separately.

## Packaged notices

Each newly built installer includes `resources/licenses/`: the full ReconBot GPL text, COPYRIGHT, this notice, actual dependency license texts and a versioned component inventory. `desktop/scripts/build-licenses.cjs` reads installed production npm packages, Electron, Python backend dependencies and the native CPython notice. It fails if a required component notice is missing. Electron/Chromium's additional runtime notices remain included by Electron's distribution.

The checked production npm dependencies declare MIT, ISC or Python-2.0 licenses. Python backend declarations include ISC, MIT, BSD-3-Clause, Apache-2.0 and MPL-2.0 (Certifi); they remain under their own terms. CPython and PyInstaller retain their notices/exception. This inventory is a build-time notice check, not a claim that every future dependency version has identical licensing.

Certifi is bundled unmodified; its package source is available at the versioned PyPI link recorded in `components.json`. Preserve its MPL notice and corresponding-source availability when redistributing. PySide6 is excluded from frozen Electron installers; developers using the legacy GUI must follow the separate Qt/PySide terms.

ReconBot source/build scripts are provided in the release source ZIP; dependency versions and upstream package links are recorded in the installer inventory. Redistributions must continue to satisfy the GPL and each component's original terms.
