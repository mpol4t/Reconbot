from reconbot.runtime import processes as subprocess
from reconbot.runtime.scanner_result import ScannerItems
from pathlib import Path
from typing import Any
from urllib.parse import urljoin
import re
import ssl
import urllib.request
from urllib.error import URLError, HTTPError
import random
import string


# Smart defaults: keep results meaningful while still surfacing auth/forbidden signals.
DEFAULT_ALLOWED_STATUS = {200, 301, 302, 401, 403}

# Prioritize high-interest paths even if we need to cap
INTERESTING_PATH_KEYWORDS = (
    "admin",
    "login",
    "signin",
    "sign-in",
    "auth",
    "oauth",
    "sso",
    "dashboard",
    "manage",
    "panel",
    "wp-admin",
    "phpmyadmin",
    "pma",
    "swagger",
    "openapi",
    "api",
    "graphql",
    "actuator",
)

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text or "")

def _cap_with_priority(items: list[dict[str, Any]], cap: int, keywords: tuple[str, ...] = INTERESTING_PATH_KEYWORDS) -> list[dict[str, Any]]:
    """Return up to `cap` items, prioritizing interesting paths first."""
    if len(items) <= cap:
        return items

    interesting = [it for it in items if any(k in str(it.get("path", "")).lower() for k in keywords)]
    other = [it for it in items if it not in interesting]

    # Keep stable order while prioritizing interesting
    out: list[dict[str, Any]] = []
    for it in interesting:
        if len(out) >= cap:
            break
        out.append(it)

    for it in other:
        if len(out) >= cap:
            break
        out.append(it)

    return out


# --- Wildcard baseline probing helpers ---
def _rand_token(n: int = 12) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(max(6, n)))


def _fetch_probe(url: str, timeout_seconds: int = 10, insecure_tls: bool = False) -> tuple[int, int]:
    """Best-effort GET probe: returns (status_code, body_size_bytes).

    - Reads at most 4096 bytes to avoid downloading large responses.
    - `body_size_bytes` is the bytes read (not Content-Length).
    """
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "reconbot-probe/1.0",
            "Accept": "*/*",
        },
        method="GET",
    )

    context = None
    if insecure_tls and url.startswith("https://"):
        try:
            context = ssl._create_unverified_context()
        except Exception:
            context = None

    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds, context=context) as resp:
            status = int(getattr(resp, "status", 0) or 0)
            data = resp.read(4096) or b""
            return status, int(len(data))
    except HTTPError as e:
        # HTTPError is also a valid HTTP response with a status code
        try:
            data = e.read(4096) or b""
        except Exception:
            data = b""
        return int(getattr(e, "code", 0) or 0), int(len(data))
    except URLError:
        return 0, 0
    except Exception:
        return 0, 0


def _detect_wildcard_baseline(
    base_url: str,
    timeout_seconds: int,
    insecure_tls: bool,
    allowed: set[int],
    probe_count: int = 2,
) -> tuple[bool, int, int]:
    """Detect wildcard/soft-404 behavior.

    We probe a few random non-existent paths. If the site returns an *allowed*
    status (esp. 200/301/302/401/403) consistently with similar body size,
    it is likely a wildcard/soft-404.

    Returns: (wildcard_detected, baseline_status, baseline_size)
    baseline_size is the sampled body size (bytes read).
    """
    if not base_url:
        return False, 0, 0

    samples: list[tuple[int, int]] = []
    for _ in range(max(1, probe_count)):
        token = _rand_token(16)
        probe_url = urljoin(base_url if base_url.endswith("/") else base_url + "/", token)
        status, size = _fetch_probe(probe_url, timeout_seconds=timeout_seconds, insecure_tls=insecure_tls)
        if status:
            samples.append((status, size))

    if len(samples) < 1:
        return False, 0, 0

    # Choose the most common status among samples
    status_counts: dict[int, int] = {}
    for s, _ in samples:
        status_counts[s] = status_counts.get(s, 0) + 1
    baseline_status = max(status_counts.items(), key=lambda kv: kv[1])[0]

    # If baseline status isn't even in our allowed set, it won't pollute results anyway.
    if baseline_status not in allowed:
        return False, baseline_status, 0

    # Compute baseline size as median-like (sorted middle)
    sizes = sorted(sz for s, sz in samples if s == baseline_status)
    baseline_size = sizes[len(sizes) // 2] if sizes else 0

    # Heuristic: if we consistently get an allowed status for random paths, treat as wildcard.
    # We require at least half of probes to match the baseline status.
    if status_counts.get(baseline_status, 0) >= max(1, len(samples) // 2):
        return True, baseline_status, baseline_size

    return False, baseline_status, baseline_size


def _normalize_base_url(url: str) -> str:
    """Normalize a base URL for gobuster.

    Accepts inputs like:
      - example.com
      - //example.com
      - http(s)://example.com[:port]

    Returns a URL with a scheme.
    """
    u = (url or "").strip()
    if not u:
        return ""

    # If something passes scheme-less URLs like //example.com
    if u.startswith("//"):
        return "https:" + u

    # If scheme is missing, default to http
    if not (u.startswith("http://") or u.startswith("https://")):
        return "http://" + u

    return u


def run_gobuster(
    url: str,
    wordlist: str,
    allowed_status: set[int] | None = None,
    threads: int = 20,
    timeout: int | str = "10s",
    timeout_sec: int | None = None,
    *,
    smart_filter: bool = True,
    max_auth_endpoints: int = 60,
    max_forbidden_endpoints: int = 60,
    wall_min_hits: int = 80,
    wall_ratio_threshold: float = 0.80,
    wall_sample_cap: int = 15,
    detect_wildcard: bool = True,
    wildcard_size_tolerance: int = 32,
    wildcard_probe_count: int = 2,
) -> list[dict[str, Any]]:
    """Run gobuster dir scan on a single base URL.

    Returns a list of dicts: {path, status, url}.
    Execution errors are recorded on the list-compatible result; partial evidence is preserved.
    """
    base_url = _normalize_base_url(url)
    if not base_url:
        raise ValueError("Gobuster target URL is empty")

    wl = (wordlist or "").strip()
    if not wl or not Path(wl).expanduser().exists():
        # Wordlist yoksa gobuster çalıştırmak anlamsız
        print(f"[!] Gobuster wordlist bulunamadı: {wl}")
        raise ValueError(f"Gobuster wordlist not found: {wl}")

    wl_path = str(Path(wl).expanduser())

    # Backward/forward compatible timeout handling:
    # - Some callers pass `timeout` as str ("10s"), others pass int seconds.
    # - Some callers use `timeout_sec`.
    # Rule: if `timeout` is explicitly provided (not None), it wins. Otherwise use `timeout_sec`.
    effective_timeout = timeout
    if effective_timeout is None and timeout_sec is not None:
        effective_timeout = timeout_sec

    # Normalize to gobuster's expected string format like "10s"
    if isinstance(effective_timeout, (int, float)):
        effective_timeout_arg = f"{int(effective_timeout)}s"
    else:
        t = str(effective_timeout).strip()
        if t.isdigit():
            effective_timeout_arg = f"{t}s"
        else:
            effective_timeout_arg = t or "10s"

    # Build the allowed status list early so we can also pass it to gobuster.
    allowed = DEFAULT_ALLOWED_STATUS if allowed_status is None else allowed_status
    allowed_codes = ",".join(str(c) for c in sorted(allowed))

    # Keep output parse-friendly (no progress bar, keep status lines)
    cmd = [
        "gobuster",
        "dir",
        "--no-progress",
        "--no-color",
        "-u",
        base_url,
        "-w",
        wl_path,
        "-t",
        str(max(1, threads)),
        "--timeout",
        effective_timeout_arg,
        "--status-codes",
        allowed_codes,
    ]

    # If HTTPS is used, allow insecure certs to avoid empty output on misconfigured TLS
    if base_url.startswith("https://"):
        cmd.append("-k")

    p1 = subprocess.run(cmd, capture_output=True, text=True)

    # Some gobuster versions treat default blacklist as "set" and conflict with --status-codes.
    # Other versions conflict when both status-codes and status-codes-blacklist are explicitly provided.
    # We detect the conflict message and retry with an alternative flag style.
    stderr_clean = _strip_ansi(p1.stderr or "")
    conflict_msg = "status-codes" in stderr_clean and "status-codes-blacklist" in stderr_clean and "both set" in stderr_clean

    if p1.returncode != 0 and conflict_msg:
        # Some versions say both are set because a default blacklist exists internally.
        # Retry by explicitly emptying the blacklist.
        cmd_with_empty_blacklist = cmd + ["--status-codes-blacklist", ""]
        p2 = subprocess.run(cmd_with_empty_blacklist, capture_output=True, text=True)
        if p2.returncode == 0 or "(Status:" in _strip_ansi(p2.stdout or "") or "(Status:" in _strip_ansi(p2.stderr or ""):
            p1 = p2

    # If gobuster fails (non-zero), decide whether we still have usable findings.
    # - If stdout or stderr contains findings, we will try to parse them.
    # - Otherwise, treat it as an error and surface stderr to the user.
    if p1.returncode != 0:
        stdout_preview = _strip_ansi(p1.stdout or "").strip()
        stderr_preview = _strip_ansi(p1.stderr or "").strip()

        # Heuristic: gobuster findings usually contain "(Status:" in the output.
        has_findings = "(Status:" in stdout_preview or "(Status:" in stderr_preview

        if not has_findings:
            if stderr_preview:
                print(f"[!] Gobuster hata (rc={p1.returncode}): {stderr_preview}")
            else:
                print(f"[!] Gobuster hata (rc={p1.returncode}). Çıktı yok.")
            return ScannerItems(returncode=p1.returncode, error=stderr_preview)
    stdout_text = _strip_ansi(p1.stdout or "")
    stderr_text = _strip_ansi(p1.stderr or "")

    # Some gobuster builds/modes may emit findings to stderr; parse both streams.
    output_text = "\n".join([t for t in (stdout_text, stderr_text) if (t or "").strip()])

    # If we still have no parseable output, return empty.
    if not (output_text or "").strip():
        return ScannerItems(returncode=p1.returncode, error=stderr_text.strip() if p1.returncode else "")

    results: list[dict[str, Any]] = []

    # Parse gobuster findings in a tolerant way.
    # Different gobuster modes/versions may output:
    #   /admin (Status: 301) [Size: ...]
    #   admin (Status: 301) [Size: ...]
    #   Found: /admin (Status: 301)
    #   http://host/admin (Status: 301)
    for raw in output_text.splitlines():
        line = (raw or "").strip()
        if not line:
            continue

        # Keep only lines that look like findings
        if "Status:" not in line:
            continue

        # Extract status code
        m_status = re.search(r"Status:\s*(\d+)", line)
        if not m_status:
            continue
        try:
            status_int = int(m_status.group(1))
        except Exception:
            continue
        if status_int not in allowed:
            continue

        # Remove common prefixes
        cleaned = line
        if cleaned.lower().startswith("found:"):
            cleaned = cleaned.split(":", 1)[1].strip()

        # Path token is usually the first token before whitespace or before '(Status:'
        before_status = cleaned.split("(Status:", 1)[0].strip()
        token = before_status.split()[0] if before_status else ""
        if not token:
            continue

        # If token is a full URL, reduce it to just path
        if token.startswith("http://") or token.startswith("https://"):
            # Keep scheme+host as base_url and store only the path portion
            try:
                from urllib.parse import urlparse
                parsed = urlparse(token)
                path = parsed.path or "/"
            except Exception:
                continue
        else:
            path = token

        # Normalize leading slash
        if not path.startswith("/"):
            path = "/" + path

        m_size = re.search(r"\[Size:\s*(\d+)\]", line)
        size_int: int | None = None
        if m_size:
            try:
                size_int = int(m_size.group(1))
            except Exception:
                size_int = None

        results.append({
            "path": path,
            "status": status_int,
            "size": size_int,
            "url": urljoin(base_url, path),
        })

    # De-dup by (status, path)
    uniq: dict[tuple[int, str], dict[str, Any]] = {}
    for item in results:
        key = (int(item.get("status", 0)), str(item.get("path", "")))
        uniq[key] = item
    results = list(uniq.values())

    # --- Wildcard / soft-404 defense ---
    # Some sites return 200/301/302 for *any* path (wildcard). That floods gobuster with garbage.
    # We probe random non-existent paths and, if detected, we drop entries that match the baseline.
    insecure_tls = base_url.startswith("https://")
    timeout_seconds_for_probe = 10
    try:
        # effective_timeout_arg is like "10s"; extract the numeric part for probe
        m_t = re.match(r"^(\d+)", str(effective_timeout_arg))
        if m_t:
            timeout_seconds_for_probe = max(3, int(m_t.group(1)))
    except Exception:
        timeout_seconds_for_probe = 10

    wildcard_detected = False
    baseline_status = 0
    baseline_size = 0
    if detect_wildcard:
        wildcard_detected, baseline_status, baseline_size = _detect_wildcard_baseline(
            base_url=base_url,
            timeout_seconds=timeout_seconds_for_probe,
            insecure_tls=insecure_tls,
            allowed=allowed,
            probe_count=wildcard_probe_count,
        )

    if wildcard_detected and baseline_status in allowed:
        before = len(results)
        filtered: list[dict[str, Any]] = []
        for r in results:
            st = int(r.get("status", 0) or 0)
            sz = r.get("size", None)

            # If size is missing, only use status match to decide (be conservative: keep).
            if st != baseline_status:
                filtered.append(r)
                continue

            if isinstance(sz, int) and baseline_size:
                if abs(sz - baseline_size) <= int(max(0, wildcard_size_tolerance)):
                    # Looks like wildcard baseline -> drop
                    continue
                filtered.append(r)
                continue

            # No size to compare -> keep (avoid false drops)
            filtered.append(r)

        dropped = before - len(filtered)
        if dropped > 0:
            print(
                "[i] Gobuster: wildcard/soft-404 detected. "
                f"Baseline Status={baseline_status}, Baseline Size~{baseline_size}. "
                f"Filtered {dropped} likely-fake hits."
            )
        results = filtered

    if not smart_filter:
        return ScannerItems(results, returncode=p1.returncode, error=stderr_text.strip() if p1.returncode else "")

    # --- Smart filtering for 401/403 to avoid floods ---
    auth_hits = [r for r in results if r.get("status") == 401]
    forbidden_hits = [r for r in results if r.get("status") == 403]
    other_hits = [r for r in results if r.get("status") not in (401, 403)]

    total_hits = len(results)
    wall_like = False
    if total_hits >= wall_min_hits:
        wall_ratio = (len(auth_hits) + len(forbidden_hits)) / max(1, total_hits)
        wall_like = wall_ratio >= wall_ratio_threshold

    if wall_like:
        # If it's wall-like, keep only a small, high-signal sample.
        auth_sample = _cap_with_priority(auth_hits, min(wall_sample_cap, max_auth_endpoints))
        forbidden_sample = _cap_with_priority(forbidden_hits, min(wall_sample_cap, max_forbidden_endpoints))
        dropped = total_hits - (len(other_hits) + len(auth_sample) + len(forbidden_sample))
        if dropped > 0:
            print(
                "[i] Gobuster: 401/403 wall detected (many endpoints return auth/forbidden). "
                f"Sampling results to prevent flood (dropped ~{dropped})."
            )
        results = other_hits + auth_sample + forbidden_sample
    else:
        # Normal case: cap 401/403 separately but keep meaningful coverage.
        auth_kept = _cap_with_priority(auth_hits, max_auth_endpoints)
        forbidden_kept = _cap_with_priority(forbidden_hits, max_forbidden_endpoints)

        if len(auth_hits) > len(auth_kept):
            print(f"[i] Gobuster: 401 sonuçları çok fazla ({len(auth_hits)}). İlk {len(auth_kept)} gösterilecek.")
        if len(forbidden_hits) > len(forbidden_kept):
            print(f"[i] Gobuster: 403 sonuçları çok fazla ({len(forbidden_hits)}). İlk {len(forbidden_kept)} gösterilecek.")

        results = other_hits + auth_kept + forbidden_kept

    # If gobuster ran but we parsed nothing, surface a hint for debugging.
    if not results:
        preview = (output_text or "").strip().splitlines()[:5]
        if preview:
            print("[i] Gobuster: çıktı var ama parse edilecek satır bulunamadı. İlk satırlar:")
            for pl in preview:
                print("[i]   " + pl)

    return ScannerItems(results, returncode=p1.returncode, error=stderr_text.strip() if p1.returncode else "")
