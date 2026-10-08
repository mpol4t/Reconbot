# dnsx_scan.py:
# TR: Keşfedilen domain ve alt domainler için DNS çözümlemesi yaparak geçerli (resolve olan) kayıtları ve ilgili DNS bilgilerini doğrular.
# EN: Performs DNS resolution on discovered domains and subdomains to validate active records and retrieve related DNS information.

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


def run_dnsx(hosts: list[str], rate_limit: int | None = None) -> list[str]:
    if not hosts:
        return []
    
    stdin_text = "\n".join(hosts)
    cmd = ["dnsx", "-silent"]
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
    subdomains = sorted(set(temiz_satırlar))
    return ScannerItems(subdomains, returncode=result.returncode, error=(result.stderr or "").strip() if result.returncode else "")
