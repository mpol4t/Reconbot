# subfinder_scan.py:
# TR: Hedef domaine ait alt domainleri pasif kaynaklardan (OSINT) toplayarak keşif kapsamını genişletir.
# EN: Enumerates subdomains of the target domain using passive OSINT sources to expand the reconnaissance scope.

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


def run_subfinder(domain: str, rate_limit: int | None = None) -> list[str]:
    target = domain.strip()
    if not target:
        print("[!] Domainde bir problem bulunmaktadır lütfen kontrol ediniz!")
        return []

    cmd = ["subfinder", "-silent", "-d", target]
    use_rate_limit = rate_limit is not None and int(rate_limit) > 0
    if use_rate_limit:
        cmd.extend(["-rl", str(int(rate_limit))])

    result = subprocess.run(cmd, capture_output=True, text=True)
    satırlar = result.stdout.splitlines()
    temiz_liste = [satır.strip() for satır in satırlar if satır.strip()]
    subdomains = sorted(set(temiz_liste))
    return ScannerItems(subdomains, returncode=result.returncode, error=(result.stderr or "").strip() if result.returncode else "")
