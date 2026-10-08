# httpx_scan.py: 
# TR: Keşfedilen hedeflerde aktif HTTP/HTTPS servislerini tespit eder ve durum kodu, başlık (title), kullanılan teknoloji gibi temel web bilgilerini toplayarak sonraki analiz adımlarına veri sağlar.
# ENG: Uses httpx to probe discovered hosts for active HTTP/HTTPS services and collect basic web metadata (status, title, tech, etc.) for further analysis.

from reconbot.runtime import processes as subprocess
from reconbot.runtime.scanner_result import ScannerItems

def _supports_flag_error(stderr_text: str) -> bool:
    low = (stderr_text or "").lower()
    return any(
        marker in low
        for marker in (
            "unknown flag",
            "unknown shorthand flag",
            "flag provided but not defined",
        )
    )


def run_httpx(hosts: list[str], rate_limit: int | None = None) -> list[str]:
    if not hosts:
        return []
    
    stdin_text = "\n".join(hosts)
    cmd = ["httpx", "-silent"]
    use_rate_limit = rate_limit is not None and int(rate_limit) > 0
    if use_rate_limit:
        cmd.extend(["-rl", str(int(rate_limit))])

    result = subprocess.run(
        cmd,
        input=stdin_text,
        capture_output=True,
        text=True
    )

    satırlar = result.stdout.splitlines()
    temiz_satırlar = [satır.strip() for satır in satırlar if satır.strip()]
    urls = sorted(set(temiz_satırlar))
    return ScannerItems(urls, returncode=result.returncode, error=(result.stderr or "").strip() if result.returncode else "")
    
    
    
