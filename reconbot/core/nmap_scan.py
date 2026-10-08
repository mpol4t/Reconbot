import ipaddress
from urllib.parse import urlparse
from reconbot.runtime import processes as subprocess
from pathlib import Path
import xml.etree.ElementTree as ET 
from datetime import datetime
import tempfile
import os 

def _normalize_nmap_timing(timing: str | None, *, fallback: str = "T4") -> str:
    raw = str(timing or "").strip().upper()
    if raw.startswith("-T"):
        raw = raw[2:]
    elif raw.startswith("T"):
        raw = raw[1:]

    if raw.isdigit():
        value = int(raw)
        if 0 <= value <= 4:
            return f"T{value}"
        if value >= 5:
            return "T4"

    fb = str(fallback or "").strip().upper()
    if fb.startswith("-T"):
        fb = fb[2:]
    elif fb.startswith("T"):
        fb = fb[1:]
    if fb.isdigit():
        fb_v = int(fb)
        if 0 <= fb_v <= 4:
            return f"T{fb_v}"
    return "T4"


def _detect_target_mode(raw_target: str) -> str:
    """Return one of: 'url', 'ip', 'domain'."""
    t = (raw_target or "").strip()
    if t.startswith("http://") or t.startswith("https://"):
        return "url"
    try:
        ipaddress.ip_address(t)
        return "ip"
    except Exception:
        return "domain"


def _normalize_target_url(raw_target: str) -> str:
    """Ensure URL has scheme; default to http:// when missing."""
    t = (raw_target or "").strip()
    if not t:
        return t
    if t.startswith("http://") or t.startswith("https://"):
        return t
    return f"http://{t}"

def run_nmap(ip: str, *, timing: str = "T4", top_ports: int = 1000, timeout_sec: int = 120, detailed: bool = False, run_dir: Path | None = None) -> tuple[str, Path]:
    if run_dir is not None:
        run_dir.mkdir(parents=True, exist_ok=True)
        xml_path = str(run_dir / "nmap.xml")
    else:
        fd, xml_path = tempfile.mkstemp(suffix=".xml")
        os.close(fd)
    timing_arg = "-" + _normalize_nmap_timing(timing, fallback="T4")
    print("[+] Nmap başlatılıyor...")
    ports = ["-Pn", "-p-"] if detailed else ["--version-light", "--top-ports", str(top_ports)]
    result = subprocess.run(
        ["nmap", "-sV", *ports, timing_arg, "--host-timeout", f"{timeout_sec}s", "-oX", xml_path, ip],
        capture_output=True,
        text=True,
        timeout=timeout_sec + 5,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr)
    else:
        # Nmap can print noisy service fingerprints starting with "SF:".
        # They are useful for debugging but ruin report readability, so we strip them.
        raw_out = result.stdout or ""
        cleaned_lines = []
        for line in raw_out.splitlines():
            if line.startswith("SF:"):
                continue
            cleaned_lines.append(line)
        cleaned_out = "\n".join(cleaned_lines).strip() + ("\n" if raw_out.endswith("\n") else "")

        print(cleaned_out)
        return cleaned_out, Path(xml_path)


def parse_nmap_xml(xml_path, ip):
    urls = []
    if not xml_path.exists():
        print("Parse edilecek XML dosyası bulunamadı!!!")
        return []
    
    tree = ET.parse(xml_path)
    root = tree.getroot()
    common_web_ports = {"80", "443", "8080", "8000", "8443", "3000", "5000"}
    for port in root.iter("port"):
        port_numarası = port.attrib["portid"]
        state_element = port.find("state")
        if state_element is None:
            continue
        state = state_element.attrib["state"]
        service_element = port.find("service")
        if service_element is None:
            continue
        servis = service_element.attrib.get("name", "")
        servis = servis.lower()

        if state != "open":
            continue

        is_http_service = "http" in servis
        is_common_web_port = port_numarası in common_web_ports

        if not (is_http_service or is_common_web_port):
            continue

        if "https" in servis or port_numarası in {"443", "8443"}:
            scheme = "https"
        else:
            scheme = "http"

        urls.append(f"{scheme}://{ip}:{port_numarası}")
    
    return urls
            


def detailed_nmap(ip: str, *, timing: str = "T4") -> subprocess.Popen:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    desktop_path = Path.home() / "Desktop" / f"detailed_nmap_{ts}.txt"
    desktop_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"[+] Detailed nmap arka planda başlatıldı {desktop_path}")
    timing_arg = "-" + _normalize_nmap_timing(timing, fallback="T4")
    
    with open(desktop_path, 'w') as file:
        proc = subprocess.Popen(
            ["nmap", "-Pn", "-p-", "-sV", "-v", timing_arg, "--stats-every", "5s", ip],
            start_new_session=True,
            stdout=file,
            stderr=file
        )

    print(f"[+] Detailed nmap PID: {proc.pid}")
    return proc
