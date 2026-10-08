import shutil
import sys

from reconbot.core.registry import TOOLS

DEFAULT_REQUIRED_TOOLS: list[str] = [t.binary for t in TOOLS if t.required]
OPTIONAL_TOOLS: list[str] = [t.binary for t in TOOLS if not t.required]


def preflight_check(required_tools: list[str] | None = None) -> None:
    """Fail fast if required external tools are missing from PATH."""
    tools = required_tools if required_tools is not None else DEFAULT_REQUIRED_TOOLS

    missing: list[str] = [t for t in tools if shutil.which(t) is None]

    if missing:
        print("[!] Eksik tool(lar) bulundu. Kurulumları tamamlamadan devam edemezsin:")
        for t in missing:
            print(f"    - {t}")

        # Helpful note for common macOS cases.
        print("\n[i] Notlar:")
        print("    - whatweb bazen alias ile gelir; `which whatweb` PATH'te değilse burada eksik sayılır.")
        print("    - gowitness Go ile kurulduysa `$HOME/go/bin` PATH'te olmalı.")
        sys.exit(1)

    # Optional tools check (warning only)
    optional_missing = [t for t in OPTIONAL_TOOLS if shutil.which(t) is None]
    if optional_missing:
        print("[i] Opsiyonel tool(lar) bulunamadı (devam ediyorum):")
        for t in optional_missing:
            print(f"    - {t}")


if __name__ == "__main__":
    preflight_check()