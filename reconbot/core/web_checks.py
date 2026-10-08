from __future__ import annotations
import re
from urllib.parse import urlsplit, urljoin, urlparse
from typing import Any
import time
import requests
import signal
import threading
from contextlib import contextmanager


class _HttpDeadlineExceeded(Exception):
    """Not an OSError, so urllib3 cannot reclassify this as a protocol failure."""


@contextmanager
def _http_deadline(seconds: float):
    """Interrupt trickling bodies/headers on the scanner's POSIX main thread."""
    supported = hasattr(signal, "setitimer") and threading.current_thread() is threading.main_thread()
    owned = supported and signal.getitimer(signal.ITIMER_REAL)[0] == 0
    if not owned:
        yield
        return
    def expired(_signal, _frame):
        raise _HttpDeadlineExceeded("Web check total request deadline exceeded")
    old = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, max(0.001, seconds))
    try:
        yield
    except _HttpDeadlineExceeded as exc:
        raise requests.Timeout(str(exc)) from exc
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def _bounded_response(session: requests.Session, url: str, *, timeout_sec: float, max_bytes: int, follow_redirects: bool = True):
    """Read at most the decoded byte budget and always release the connection."""
    deadline = time.monotonic() + timeout_sec
    with _http_deadline(timeout_sec):
        response = session.get(url, timeout=timeout_sec, allow_redirects=follow_redirects, stream=True)
        try:
            body = bytearray()
            # read1 yields available data; it does not wait for a full large chunk.
            reader = getattr(response.raw, "read1", None)
            chunks = None if reader else response.iter_content(chunk_size=1)
            while len(body) < max_bytes:
                if time.monotonic() >= deadline:
                    raise requests.Timeout("Web check total request deadline exceeded")
                amount = min(8192, max_bytes - len(body))
                chunk = reader(amount, decode_content=True) if reader else next(chunks, b"")
                if not chunk:
                    break
                body.extend(chunk[:amount])
            encoding = response.encoding or "utf-8"
            try:
                text = body.decode(encoding, errors="replace")
            except LookupError:
                text = body.decode("utf-8", errors="replace")
            return response, text
        finally:
            response.close()


# --- Simple detection patterns (fast heuristics, not perfect) ---
_LOGIN_URL_KEYWORDS = (
    "login",
    "signin",
    "sign-in",
    "auth",
    "session",
)

_DOCS_URL_KEYWORDS = (
    "swagger",
    "openapi",
    "api-docs",
    "redoc",
    "docs",
    "documentation",
)

# Lightweight technology / WAF fingerprint hints
_SERVER_TECH_HINTS = {
    "nginx": "Nginx",
    "apache": "Apache HTTPD",
    "openresty": "OpenResty",
    "iis": "Microsoft IIS",
    "caddy": "Caddy",
    "gunicorn": "Gunicorn",
    "uvicorn": "Uvicorn",
    "express": "Express",
    "cloudflare": "Cloudflare",
}

_POWERED_BY_HINTS = {
    "php": "PHP",
    "asp.net": "ASP.NET",
    "express": "Express",
    "next.js": "Next.js",
    "laravel": "Laravel",
}

_BODY_TECH_HINTS = {
    "wp-content": "WordPress",
    "wp-includes": "WordPress",
    "wordpress": "WordPress",
    "drupal": "Drupal",
    "joomla": "Joomla",
    "laravel": "Laravel",
    "django": "Django",
    "__next": "Next.js",
    "react": "React",
    "vue": "Vue.js",
    "angular": "Angular",
    "graphql": "GraphQL",
    "swagger-ui": "Swagger UI",
    "redoc": "ReDoc",
}

_WAF_HINT_HEADERS = {
    "cf-ray": "Cloudflare",
    "x-sucuri-id": "Sucuri",
    "x-sucuri-cache": "Sucuri",
    "x-cdn": "CDN/WAF",
    "x-akamai": "Akamai",
}

# Captcha markers in HTML
_CAPTCHA_MARKERS = (
    ("recaptcha", "reCAPTCHA"),
    ("g-recaptcha", "reCAPTCHA"),
    ("hcaptcha", "hCaptcha"),
    ("data-sitekey", "Captcha (sitekey present)"),
    ("cf-turnstile", "Cloudflare Turnstile"),
    ("turnstile", "Cloudflare Turnstile"),
)

# Basic login form markers
_PASSWORD_INPUT_REGEX = re.compile(r"type\s*=\s*['\"]password['\"]", re.IGNORECASE)

# JS asset scanning limits (to keep runtime predictable)
_MAX_SCRIPT_URLS = 10
_MAX_JS_BYTES = 1_500_000  # ~1.5MB

_SCRIPT_SRC_REGEX = re.compile(r"<script[^>]+src=['\"]([^'\"]+)['\"]", re.IGNORECASE)


class _RequestThrottle:
    """Simple in-process throttle for passive HTTP checks.

    Supports:
    - fixed delay between requests
    - max requests per second pacing
    """

    def __init__(self, *, requests_per_second: int = 0, delay_ms: int = 0) -> None:
        self.requests_per_second = max(0, int(requests_per_second or 0))
        self.delay_ms = max(0, int(delay_ms or 0))
        self._last_request_at = 0.0

    def wait(self) -> None:
        now = time.monotonic()
        wait_seconds = 0.0

        if self.delay_ms > 0:
            wait_seconds = max(wait_seconds, self.delay_ms / 1000.0)

        if self.requests_per_second > 0:
            min_interval = 1.0 / float(self.requests_per_second)
            elapsed = now - self._last_request_at if self._last_request_at else float("inf")
            if elapsed < min_interval:
                wait_seconds = max(wait_seconds, min_interval - elapsed)

        if wait_seconds > 0:
            time.sleep(wait_seconds)

        self._last_request_at = time.monotonic()

def _same_origin(url_a: str, url_b: str) -> bool:
    """Return True if two URLs share the same scheme+netloc (origin)."""
    try:
        pa = urlparse(url_a)
        pb = urlparse(url_b)
        return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)
    except Exception:
        return False

def _extract_script_src_urls(html_text: str) -> list[str]:
    """Extract <script src="..."> URLs from HTML (raw values, may be relative)."""
    srcs = []
    for m in _SCRIPT_SRC_REGEX.finditer(html_text or ""):
        src = (m.group(1) or "").strip()
        if src:
            srcs.append(src)
    return srcs

def _detect_captcha_in_js_assets(
    *,
    session: requests.Session,
    page_url: str,
    html_text: str,
    timeout_sec: int,
    throttle: _RequestThrottle | None = None,
    follow_redirects: bool = True,
    max_body_bytes: int = 200_000,
) -> str | None:
    """Try to detect captcha markers inside JS assets referenced by the page.

    This is still passive: it only downloads a limited number of JS files and searches for markers.
    """

    # Get up to N script URLs
    raw_srcs = _extract_script_src_urls(html_text)
    if not raw_srcs:
        return None

    # Resolve to absolute URLs
    absolute_script_urls: list[str] = []
    seen: set[str] = set()

    for raw_src in raw_srcs:
        abs_url = urljoin(page_url, raw_src)
        if abs_url in seen:
            continue
        seen.add(abs_url)
        absolute_script_urls.append(abs_url)
        if len(absolute_script_urls) >= _MAX_SCRIPT_URLS:
            break

    # Prefer same-origin scripts first to avoid fetching many third-party libraries
    same_origin_scripts = [u for u in absolute_script_urls if _same_origin(page_url, u)]
    other_scripts = [u for u in absolute_script_urls if u not in same_origin_scripts]
    scripts_to_fetch = (same_origin_scripts + other_scripts)[:_MAX_SCRIPT_URLS]

    for script_url in scripts_to_fetch:
        try:
            if throttle is not None:
                throttle.wait()
            resp, js_text = _bounded_response(session, script_url, timeout_sec=timeout_sec, max_bytes=min(_MAX_JS_BYTES, max_body_bytes), follow_redirects=follow_redirects)
            content_type = str(resp.headers.get("Content-Type", ""))

            # Even if content-type is missing, we still try, but we limit bytes.
            captcha_type = _detect_captcha_type(js_text)
            if captcha_type:
                return f"{captcha_type} (JS asset)"

            # Extra strong hints: known captcha script endpoints
            lower_text = js_text.lower()
            if "google.com/recaptcha" in lower_text:
                return "reCAPTCHA (JS asset hint)"
            if "hcaptcha.com/1/api.js" in lower_text:
                return "hCaptcha (JS asset hint)"
            if "challenges.cloudflare.com/turnstile" in lower_text:
                return "Cloudflare Turnstile (JS asset hint)"

        except Exception:
            # Ignore individual script failures to keep checks resilient
            continue

    return None


def _looks_like_login_url(url: str) -> bool:
    url_lower = (url or "").lower()
    return any(keyword in url_lower for keyword in _LOGIN_URL_KEYWORDS)


def _looks_like_docs_url(url: str) -> bool:
    url_lower = (url or "").lower()
    return any(keyword in url_lower for keyword in _DOCS_URL_KEYWORDS)


def _detect_captcha_type(html_text: str) -> str | None:
    html_lower = (html_text or "").lower()
    for marker, captcha_name in _CAPTCHA_MARKERS:
        if marker in html_lower:
            return captcha_name
    return None


def _has_password_input(html_text: str) -> bool:
    return bool(_PASSWORD_INPUT_REGEX.search(html_text or ""))


def _extract_rate_limit_signals(status_code: int, headers: dict[str, str]) -> list[str]:
    signals: list[str] = []

    # Status code based signal
    if status_code == 429:
        signals.append("HTTP 429 Too Many Requests")

    # Header based signals
    normalized_headers = {k.lower(): v for k, v in (headers or {}).items()}

    if "retry-after" in normalized_headers:
        signals.append(f"Retry-After: {normalized_headers['retry-after']}")

    for header_name in ("x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset"):
        if header_name in normalized_headers:
            signals.append(f"{header_name}: {normalized_headers[header_name]}")

    return signals


def _extract_technology_fingerprint(final_url: str, headers: dict[str, str], html_text: str) -> dict[str, Any]:
    """Best-effort lightweight technology fingerprint from headers/body."""
    normalized_headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    html_lower = (html_text or "").lower()

    server_header = normalized_headers.get("server", "")
    powered_by_header = normalized_headers.get("x-powered-by", "")
    technologies: list[str] = []
    waf_signals: list[str] = []

    server_lower = server_header.lower()
    for needle, label in _SERVER_TECH_HINTS.items():
        if needle in server_lower and label not in technologies:
            technologies.append(label)

    powered_by_lower = powered_by_header.lower()
    for needle, label in _POWERED_BY_HINTS.items():
        if needle in powered_by_lower and label not in technologies:
            technologies.append(label)

    for needle, label in _BODY_TECH_HINTS.items():
        if needle in html_lower and label not in technologies:
            technologies.append(label)

    for header_name, label in _WAF_HINT_HEADERS.items():
        if header_name in normalized_headers and label not in waf_signals:
            waf_signals.append(label)

    if "server" in normalized_headers and "cloudflare" in server_lower and "Cloudflare" not in waf_signals:
        waf_signals.append("Cloudflare")

    return {
        "site": final_url,
        "server": server_header,
        "x_powered_by": powered_by_header,
        "technologies": technologies,
        "waf_signals": waf_signals,
    }


def run_web_checks(
    urls: list[str],
    *,
    max_urls: int = 60,
    timeout_sec: int = 8,
    requests_per_second: int = 0,
    delay_ms: int = 0,
    max_body_bytes: int = 200_000,
    follow_redirects: bool = True,
) -> dict[str, Any]:
    """Run lightweight web checks on a list of URLs.

    What it tries to detect (heuristics):
    - Login pages (URL keyword OR password input in HTML)
    - Captcha presence (reCAPTCHA / hCaptcha / Turnstile markers)
    - API docs (Swagger/OpenAPI/Redoc markers)
    - Rate-limit signals (429, Retry-After, X-RateLimit-*)

    Returns a dict with lists of findings.

    Notes:
    - This is NOT an exploit. It only performs GET requests and string checks.
    - We intentionally cap the number of URLs to keep runtime predictable.
    """

    # --- Output structure ---
    findings: dict[str, Any] = {
        "checked_count": 0,
        "errors": [],
        "login_pages": [],
        "captcha_pages": [],
        "docs_pages": [],
        "rate_limit_signals": [],
        "captcha_coverage": [],
        "captcha_risk_notes": [],
        "technology_fingerprint": [],
    }

    # --- Normalize input list (clean + de-dup, keep stable order) ---
    cleaned_urls: list[str] = []
    seen_urls: set[str] = set()

    for candidate_url in urls or []:
        url_text = (candidate_url or "").strip()
        if not url_text:
            continue
        if url_text in seen_urls:
            continue
        cleaned_urls.append(url_text)
        seen_urls.add(url_text)

    urls_to_check = cleaned_urls[: max(0, max_urls)]

    # Track captcha coverage per site to spot inconsistent enforcement
    site_captcha_map: dict[str, dict[str, list[str]]] = {}
    # structure: {"scheme://netloc": {"login_with": [...], "login_without": [...], "auth_with": [...], "auth_without": [...]}}

    # --- Use a session (connection reuse = faster) ---
    session = requests.Session()
    session.headers.update({
        "User-Agent": "ReconBot/1.0 (web-checks)"
    })
    throttle = _RequestThrottle(requests_per_second=requests_per_second, delay_ms=delay_ms)

    try:
        for target_url in urls_to_check:
            try:
                throttle.wait()
                # Follow redirects ONCE to avoid loops and to keep it fast.
                response, response_text = _bounded_response(
                    session,
                    target_url,
                    timeout_sec=timeout_sec,
                    max_bytes=max_body_bytes,
                    follow_redirects=follow_redirects,
                )

                status_code = int(getattr(response, "status_code", 0) or 0)
                response_headers = dict(getattr(response, "headers", {}) or {})

                findings["checked_count"] += 1

                # --- Captcha detection ---
                page_final_url = getattr(response, "url", target_url) or target_url
                tech_fp = _extract_technology_fingerprint(page_final_url, response_headers, response_text)
                findings["technology_fingerprint"].append(tech_fp)
                captcha_type = _detect_captcha_type(response_text)

                # If HTML didn't show captcha markers, try JS assets for login/auth-like pages.
                looks_like_login = _looks_like_login_url(page_final_url)
                has_password_field = _has_password_input(response_text)
                is_login_like_for_js = looks_like_login or has_password_field
                is_auth_like_for_js = any(k in page_final_url.lower() for k in ("/api/", "auth", "token", "session", "oauth", "sso"))

                if not captcha_type and (is_login_like_for_js or is_auth_like_for_js):
                    captcha_type = _detect_captcha_in_js_assets(
                        session=session,
                        page_url=page_final_url,
                        html_text=response_text,
                        timeout_sec=timeout_sec,
                        throttle=throttle,
                        follow_redirects=follow_redirects,
                        max_body_bytes=max_body_bytes,
                    )

                if captcha_type:
                    findings["captcha_pages"].append({
                        "url": page_final_url,
                        "status": status_code,
                        "type": captcha_type,
                    })

                # --- Rate limit signals ---
                rate_signals = _extract_rate_limit_signals(status_code, response_headers)
                if rate_signals:
                    findings["rate_limit_signals"].append({
                        "url": target_url,
                        "signals": rate_signals,
                        "status": status_code,
                    })

                # --- Login detection ---
                # (already computed above using the final URL)
                looks_like_login = _looks_like_login_url(page_final_url)
                has_password_field = _has_password_input(response_text)

                # --- Captcha coverage bookkeeping (no bypass, only consistency signals) ---
                # Site key: group by scheme+netloc so we compare pages within the same site
                parsed = urlsplit(page_final_url)
                site_key = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else target_url

                if site_key not in site_captcha_map:
                    site_captcha_map[site_key] = {
                        "login_with": [],
                        "login_without": [],
                        "auth_with": [],
                        "auth_without": [],
                    }

                # Define "auth-like" URLs (API/login endpoints) by keywords in URL
                url_for_classification = page_final_url
                is_login_like = looks_like_login or has_password_field
                is_auth_like = any(k in url_for_classification.lower() for k in ("/api/", "auth", "token", "session", "oauth", "sso"))

                has_captcha = bool(captcha_type)
                if is_login_like:
                    (site_captcha_map[site_key]["login_with"] if has_captcha else site_captcha_map[site_key]["login_without"]).append(url_for_classification)
                if is_auth_like:
                    (site_captcha_map[site_key]["auth_with"] if has_captcha else site_captcha_map[site_key]["auth_without"]).append(url_for_classification)

                if looks_like_login or has_password_field:
                    reason_parts: list[str] = []
                    if looks_like_login:
                        reason_parts.append("url_keyword")
                    if has_password_field:
                        reason_parts.append("password_input")

                    findings["login_pages"].append({
                        "url": target_url,
                        "status": status_code,
                        "reason": ",".join(reason_parts),
                    })

                # --- Docs detection ---
                looks_like_docs = _looks_like_docs_url(target_url)
                html_mentions_docs = any(
                    marker in (response_text or "").lower()
                    for marker in ("swagger", "openapi", "redoc")
                )

                if looks_like_docs or html_mentions_docs:
                    reason_parts: list[str] = []
                    if looks_like_docs:
                        reason_parts.append("url_keyword")
                    if html_mentions_docs:
                        reason_parts.append("html_marker")

                    findings["docs_pages"].append({
                        "url": target_url,
                        "status": status_code,
                        "reason": ",".join(reason_parts),
                    })

            except Exception as exception:
                findings["errors"].append({
                    "url": target_url,
                    "error": str(exception),
                })

    finally:
        session.close()

    # --- Captcha coverage summary (heuristics) ---
    for site_key, buckets in site_captcha_map.items():
        login_with = sorted(set(buckets["login_with"]))
        login_without = sorted(set(buckets["login_without"]))
        auth_with = sorted(set(buckets["auth_with"]))
        auth_without = sorted(set(buckets["auth_without"]))

        # Only report when we have at least one login-like or auth-like page
        if not (login_with or login_without or auth_with or auth_without):
            continue

        findings["captcha_coverage"].append({
            "site": site_key,
            "login_with_captcha": login_with,
            "login_without_captcha": login_without,
            "auth_with_captcha": auth_with,
            "auth_without_captcha": auth_without,
        })

        # Risk notes: inconsistent captcha presence across login/auth surfaces
        if login_with and login_without:
            findings["captcha_risk_notes"].append(
                f"{site_key}: Captcha bazı login-benzeri sayfalarda var, bazılarında yok (tutarsızlık). Bu, enforcement zayıf olabilir sinyali; yetkili pentest ile doğrulanmalı."
            )
        if auth_without and (login_with or auth_with):
            findings["captcha_risk_notes"].append(
                f"{site_key}: Auth/API-benzeri URL'lerde captcha izi yok. Captcha yalnızca frontend'de olabilir (bypass riski artar); yetkili pentest ile doğrulanmalı."
            )

    # de-duplicate technology fingerprints by site while preserving first observation
    tech_seen: set[str] = set()
    tech_deduped: list[dict[str, Any]] = []
    for item in findings.get("technology_fingerprint", []) or []:
        if not isinstance(item, dict):
            continue
        site = str(item.get("site") or "")
        key = site.lower()
        if not key or key in tech_seen:
            continue
        tech_seen.add(key)
        tech_deduped.append(item)
    findings["technology_fingerprint"] = tech_deduped

    findings["throttle"] = {
        "requests_per_second": int(requests_per_second or 0),
        "delay_ms": int(delay_ms or 0),
    }

    return findings
