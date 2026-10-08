"""Run on each target OS/architecture; never cross-compile the Python runtime."""
from pathlib import Path
import subprocess
import sys
import os

desktop = Path(__file__).resolve().parents[1]
root = desktop.parent
build_dir = Path(os.environ.get("RECONBOT_BACKEND_BUILD_DIR", str(desktop / "build"))).resolve()
subprocess.run([
    sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir",
    "--name", "reconbot-backend", "--distpath", str(build_dir / "backend"),
    "--workpath", str(build_dir / "pyinstaller"),
    "--specpath", str(build_dir), "--paths", str(root),
    "--collect-submodules", "reconbot", "--collect-all", "tldextract",
    "--collect-submodules", "dns", "--collect-data", "certifi",
    "--add-data", f"{root / 'reconbot/ai/settings_contract.json'}:reconbot/ai",
    "--add-data", f"{root / 'reconbot/report/assets'}:reconbot/report/assets",
    "--exclude-module", "PySide6", "--exclude-module", "reconbot.gui.desktop_app",
    str(desktop / "scripts" / "backend-entry.py"),
], cwd=root, check=True)
