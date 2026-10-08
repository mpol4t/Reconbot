from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any
from urllib.parse import urlparse, parse_qsl, urlencode
import re

import requests


try:  # BeautifulSoup is optional; we fall back to regex if missing
    from bs4 import BeautifulSoup  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    BeautifulSoup = None  # type: ignore


# URL / body keywords that commonly indicate auth flows
AUTH_KEYWORDS = (
    "login",
    "signin",
    "sign-in",
    "auth",
    "oauth",
    "sso",
    "session",
    "register",
    "signup",
    "sign-up",
    "logout",
    "reset",
    "forgot",
    "lostpassword",
    "xmlrpc",
)

_CSRF_NAME_HINTS = (
    "csrf",
    "xsrf",
    "authenticity_token",
    "_token",
)

_CAPTCHA_MARKERS = (
    "g-recaptcha",
    "recaptcha",
    "hcaptcha",
    "cf-turnstile",
    "data-sitekey",
)

_LOCKOUT_PHRASES = (
    "too many attempts",
    "too many failed",
    "temporarily locked",
    "account locked",
    "try again later",
    "slow down",
    "rate limit",
)

_MAX_PROBED_CANDIDATES = 25
_HTTP_TIMEOUT_SEC = 8
_MAX_BODY_BYTES = 300_000


@dataclass
class AuthCandidate:
    url: str
    source: str
    status: int | None
    reason: str
    kind: str = "unknown"  # html_form / json_api / xmlrpc / oauth / sso / unknown

    # Lightweight profiler output
    final_url: str | None = None
    http_status: int | None = None
    content_type: str | None = None

    has_form: bool = False
    form_action: str | None = None
    guessed_method: str = "GET"
    has_password_field: bool = False
    has_csrf_token_hint: bool = False
    has_captcha: bool = False
    has_register_hint: bool = False
    has_reset_hint: bool = False
    has_logout_hint: bool = False
    has_remember_me_hint: bool = False

    redirect_target: str | None = None
    rate_limit_hints: list[str] | None = None
    lockout_hints: list[str] | None = None
    notes: list[str] | None = None

    confidence: int = 0


def _is_static_or_resource_url(url: str) -> bool:
    """Return True if URL clearly points to a static/admin asset, not an auth workflow.

    This must be stricter than generic asset detection: we do NOT want JS/CSS/admin
    resource loaders to ever become auth candidates, even if their paths/queries
    contain login/admin/oauth keywords.
    """
    low = (url or "").lower()
    if not low:
        return False

    # Extension-based static/resource detection
    static_exts = (
        ".js",
        ".css",
        ".map",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".webp",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
    )
    if any(low.endswith(ext) for ext in static_exts):
        return True

    # Path patterns for WordPress and generic admin resource loaders
    resource_markers = (
        "/wp-includes/js/",
        "/wp-includes/css/",
        "/wp-content/themes/",
        "/wp-content/plugins/",
        "/wp-content/uploads/",
        "/wp-admin/load-styles.php",
        "/wp-admin/load-scripts.php",
        "/wp-admin/js/",
        "/assets/",
        "/static/",
        "/dist/",
        "/fonts/",
        "/css/",
        "/js/",
    )
    if any(marker in low for marker in resource_markers):
        return True

    return False


def _is_auth_workflow_url(url: str) -> bool:
    """Return True only for real auth workflow endpoints/pages.

    - Reject obvious static/resource/admin asset URLs.
    - Allow login/wp-admin/xmlrpc/oauth/sso/etc. pages that represent workflows.
    """
    raw = (url or "").strip()
    if not raw:
        return False

    if _is_static_or_resource_url(raw):
        return False

    try:
        parsed = urlparse(raw)
        path = parsed.path or "/"
    except Exception:
        return False

    low_path = path.lower()

    # Common auth workflow paths
    auth_paths = (
        "/wp-login.php",
        "/wp-admin",
        "/wp-admin/",
        "/xmlrpc.php",
    )
    if low_path in auth_paths:
        return True

    # Paths containing meaningful auth fragments
    auth_markers = (
        "login",
        "signin",
        "sign-in",
        "auth",
        "session",
        "lostpassword",
        "reset",
        "forgot",
        "logout",
        "register",
        "signup",
        "sign-up",
        "xmlrpc",
        "oauth",
        "sso",
    )
    if any(marker in low_path for marker in auth_markers):
        return True

    # Otherwise, treat as non-auth for profiler purposes.
    return False


def _normalize_url(url: str) -> str:
    """Normalize URL for auth flow identity.

    - Keep scheme+host+path normalized.
    - Preserve auth-flow–relevant query params (e.g. action=lostpassword).
    - Drop obvious noise/tracking params.
    """
    raw = (url or "").strip()
    if not raw:
        return ""
    try:
        parsed = urlparse(raw)
        scheme = parsed.scheme or "http"
        netloc = parsed.netloc or ""
        path = parsed.path or "/"
        if path != "/":
            path = path.rstrip("/") or "/"

        # Auth-relevant query parameters we want to preserve in identity
        AUTH_QUERY_KEYS = {
            "action",
            "redirect_to",
            "reauth",
            "flow",
            "mode",
            "oauth",
            "sso",
            "return",
            "next",
            "redirect",
            "redirect_uri",
            "continue",
            "dest",
            "destination",
            "state",
            "client_id",
            "response_type",
            "scope",
            "code",
            "token",
        }

        # Obvious noise/tracking params we can safely ignore for auth identity
        NOISE_QUERY_KEYS = {
            "utm_source",
            "utm_medium",
            "utm_campaign",
            "utm_term",
            "utm_content",
            "gclid",
            "fbclid",
            "source",
            "ref",
            "rand",
        }

        kept_params: list[tuple[str, str]] = []
        for k, v in parse_qsl(parsed.query, keep_blank_values=False):
            k_lower = k.lower()
            if k_lower in NOISE_QUERY_KEYS:
                continue
            if k_lower in AUTH_QUERY_KEYS:
                kept_params.append((k_lower, v))

        query = urlencode(kept_params, doseq=True)
        base = f"{scheme}://{netloc}{path}"
        if query:
            return f"{base}?{query}"
        return base
    except Exception:
        return raw


def _has_any_keyword(text: str, keywords: tuple[str, ...]) -> bool:
    low = (text or "").lower()
    return any(k in low for k in keywords)


def _merge_unique_candidates(existing: dict[str, AuthCandidate], new: AuthCandidate) -> None:
    key = _normalize_url(new.url)
    if not key:
        return
    if key not in existing:
        existing[key] = new
        return
    current = existing[key]
    if new.confidence > current.confidence:
        existing[key] = new


def _classify_initial_candidates(
    login_pages: list[dict[str, Any]],
    captcha_pages: list[dict[str, Any]],
    reportworthy_buckets: dict[str, Any],
) -> dict[str, AuthCandidate]:
    """Seed candidates from existing web-check and endpoint-analysis signals.

    Strong candidates come from explicit login checks; auth/admin buckets are weaker hints.
    Docs pages are *not* turned into candidates here; they are only hints later.
    """
    auth_like_urls = reportworthy_buckets.get("auth_like", []) or []
    admin_like_urls = reportworthy_buckets.get("admin_like", []) or []

    candidates: dict[str, AuthCandidate] = {}

    # Strong seeds: login_pages from web checks
    for item in login_pages:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "").strip()
        if not url:
            continue
        if not _is_auth_workflow_url(url):
            continue
        status = item.get("status") or item.get("status_code")
        has_pwd = bool(item.get("has_password") or item.get("password_field"))
        has_csrf = bool(item.get("has_csrf") or item.get("csrf_token"))
        has_cap = bool(item.get("has_captcha") or item.get("captcha_hint"))

        base_conf = 40
        if has_pwd:
            base_conf += 30  # real form + password == strongest signal
        if has_csrf:
            base_conf += 10
        if has_cap:
            base_conf += 5

        cand = AuthCandidate(
            url=url,
            source="web_checks_login",
            status=int(status or 0) if status is not None else None,
            reason=str(item.get("reason") or "login_page").strip(),
            kind="unknown",
            has_password_field=has_pwd,
            guessed_method=str(item.get("method") or "GET"),
            has_csrf_token_hint=has_csrf,
            has_captcha=has_cap,
            has_register_hint=bool(item.get("has_register")),
            has_reset_hint=bool(item.get("has_reset")),
            has_logout_hint=bool(item.get("has_logout")),
            has_remember_me_hint=bool(item.get("has_remember_me")),
            redirect_target=str(item.get("redirect_target") or "") or None,
            rate_limit_hints=list(item.get("rate_limit_hints") or []),
            confidence=min(100, base_conf),
        )
        _merge_unique_candidates(candidates, cand)

    # Captcha-only pages should mostly reinforce existing candidates, not create new strong ones.
    for item in captcha_pages:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "").strip()
        if not url:
            continue
        if not _is_auth_workflow_url(url):
            continue
        key = _normalize_url(url)
        existing = candidates.get(key)
        if existing:
            existing.has_captcha = True
            existing.confidence = min(100, existing.confidence + 5)
            continue
        status = item.get("status") or item.get("status_code")
        cand = AuthCandidate(
            url=url,
            source="web_checks_captcha",
            status=int(status or 0) if status is not None else None,
            reason=str(item.get("type") or "captcha_page"),
            kind="unknown",
            has_captcha=True,
            confidence=25,  # weaker than real login form
        )
        _merge_unique_candidates(candidates, cand)

    # Medium strength hints from endpoint-analysis auth_like bucket
    for url in auth_like_urls:
        u = str(url or "").strip()
        if not u:
            continue
        if not _is_auth_workflow_url(u):
            continue
        key = _normalize_url(u)
        existing = candidates.get(key)
        if existing:
            existing.reason += " | endpoint_analysis:auth_like"
            existing.confidence = min(100, existing.confidence + 5)
            continue
        cand = AuthCandidate(
            url=u,
            source="endpoint_analysis_auth_like",
            status=None,
            reason="endpoint_analysis:auth_like",
            kind="unknown",
            confidence=30,  # medium strength, below strong login forms
        )
        _merge_unique_candidates(candidates, cand)

    # Weak hints from admin_like bucket; strengthened only if later redirect-to-login evidence appears.
    for url in admin_like_urls:
        u = str(url or "").strip()
        if not u:
            continue
        if not _is_auth_workflow_url(u):
            continue
        key = _normalize_url(u)
        existing = candidates.get(key)
        note = " | endpoint_analysis:admin_like"
        if existing:
            existing.reason += note
            existing.confidence = min(100, existing.confidence + 3)
            continue
        # admin_like alone should never dominate a true login form
        cand = AuthCandidate(
            url=u,
            source="endpoint_analysis_admin_like",
            status=None,
            reason="endpoint_analysis:admin_like",
            kind="unknown",
            confidence=15,
        )
        _merge_unique_candidates(candidates, cand)

    return candidates


def _attach_rate_limit_hints(candidates: dict[str, AuthCandidate], rate_signals: list[dict[str, Any]]) -> None:
    rate_hint_map: dict[str, list[str]] = {}
    for item in rate_signals:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "").strip()
        if not url:
            continue
        if not _is_auth_workflow_url(url):
            continue
        key = _normalize_url(url)
        hints = [str(h) for h in (item.get("signals") or []) if h]
        if not hints:
            continue
        rate_hint_map.setdefault(key, []).extend(hints)

    for key, hints in rate_hint_map.items():
        cand = candidates.get(key)
        if not cand:
            continue
        existing = list(cand.rate_limit_hints or [])
        cand.rate_limit_hints = existing + hints
        cand.confidence = min(100, cand.confidence + 4)


def _probe_auth_candidate(session: requests.Session, cand: AuthCandidate) -> None:
    """Lightweight GET profiling for a single candidate.

    No brute force, no credential attempts, limited body size and timeout.
    """
    url = cand.url
    try:
        resp = session.get(url, timeout=_HTTP_TIMEOUT_SEC, allow_redirects=True, stream=True)
    except Exception as exc:
        notes = list(cand.notes or [])
        notes.append(f"probe_error:{exc.__class__.__name__}")
        cand.notes = notes
        return

    cand.http_status = resp.status_code
    cand.content_type = str(resp.headers.get("Content-Type", "") or "")
    cand.final_url = resp.url or cand.url

    # Redirect target hint (e.g. admin -> login)
    try:
        norm_initial = _normalize_url(cand.url)
        norm_final = _normalize_url(cand.final_url or "")
        if norm_final and norm_final != norm_initial:
            cand.redirect_target = cand.final_url
            notes = list(cand.notes or [])
            notes.append(f"redirect:{norm_initial}->{norm_final}")
            cand.notes = notes
    except Exception:
        pass

    # Header-based rate-limit / lockout hints
    rate_hints = list(cand.rate_limit_hints or [])
    lockout_hints = list(cand.lockout_hints or [])

    headers_lower = {str(k or "").lower(): str(v or "") for k, v in (resp.headers or {}).items()}
    if "retry-after" in headers_lower:
        rate_hints.append(f"Retry-After: {headers_lower['retry-after']}")
    for name in ("x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset"):
        if name in headers_lower:
            rate_hints.append(f"{name}: {headers_lower[name]}")

    cand.rate_limit_hints = rate_hints or None

    # Body (limited)
    collected: list[bytes] = []
    total = 0
    try:
        for chunk in resp.iter_content(chunk_size=65536):
            if not chunk:
                continue
            collected.append(chunk)
            total += len(chunk)
            if total >= _MAX_BODY_BYTES:
                break
    except Exception:
        pass

    try:
        body = b"".join(collected).decode("utf-8", errors="replace")
    except Exception:
        body = ""

    lower_body = (body or "").lower()
    for phrase in _LOCKOUT_PHRASES:
        if phrase in lower_body:
            lockout_hints.append(phrase)
    cand.lockout_hints = lockout_hints or None

    # Captcha markers in body
    for marker in _CAPTCHA_MARKERS:
        if marker in lower_body:
            cand.has_captcha = True
            break

    # HTML / JSON classification
    ctype = cand.content_type or ""
    is_html = "html" in ctype or (not ctype and "<html" in lower_body)
    is_json = "json" in ctype
    is_xml = "xml" in ctype or "<xml" in lower_body or "xmlrpc" in lower_body

    if is_json:
        cand.kind = "json_api"

    if is_xml and "xmlrpc" in lower_body:
        cand.kind = "xmlrpc"

    if "oauth" in lower_body or "openid" in lower_body or "sso" in lower_body:
        cand.kind = "oauth" if "oauth" in lower_body else "sso"

    if not is_html or not body:
        return

    # HTML parsing: prefer BeautifulSoup when available, fallback to regex.
    has_form = False
    has_pwd = cand.has_password_field
    has_csrf = cand.has_csrf_token_hint
    has_remember = cand.has_remember_me_hint
    has_register = cand.has_register_hint
    has_reset = cand.has_reset_hint
    has_logout = cand.has_logout_hint
    form_action: str | None = None
    guessed_method = cand.guessed_method or "GET"

    if BeautifulSoup is not None:  # type: ignore[truthy-function]
        try:
            soup = BeautifulSoup(body, "html.parser")  # type: ignore[call-arg]
            forms = soup.find_all("form")
            if forms:
                has_form = True

                # Choose the most auth-relevant form instead of always taking the first one.
                auth_keywords = (
                    "login",
                    "signin",
                    "sign-in",
                    "auth",
                    "session",
                    "register",
                    "signup",
                    "sign-up",
                    "reset",
                    "forgot",
                    "password",
                )

                def _score_form(form: Any) -> int:
                    score = 0
                    # Password field is the strongest signal
                    for inp in form.find_all("input"):
                        t = (inp.get("type") or "").lower()
                        if t == "password":
                            score += 20
                            break
                    # Look for auth keywords in id/class/name/text
                    text_parts: list[str] = []
                    fid = form.get("id") or ""
                    if isinstance(fid, str):
                        text_parts.append(fid)
                    classes = form.get("class") or []
                    if isinstance(classes, (list, tuple)):
                        text_parts.extend([str(c) for c in classes])
                    name = form.get("name") or ""
                    if isinstance(name, str):
                        text_parts.append(name)
                    # Only take a slice of inner text to keep things cheap
                    inner_text = " ".join(form.stripped_strings)[:200]
                    text_parts.append(inner_text)
                    text_blob = " ".join(text_parts).lower()
                    if any(k in text_blob for k in auth_keywords):
                        score += 10
                    return score

                chosen_form = max(forms, key=_score_form)

                action = chosen_form.get("action")
                if isinstance(action, str) and action:
                    form_action = action
                method = chosen_form.get("method") or guessed_method
                guessed_method = str(method).upper() or "GET"

                # Inputs from the chosen form
                for inp in chosen_form.find_all("input"):
                    t = (inp.get("type") or "").lower()
                    name = (inp.get("name") or "").lower()
                    if t == "password":
                        has_pwd = True
                    if any(h in name for h in _CSRF_NAME_HINTS):
                        has_csrf = True
                    if t in {"checkbox"} and "remember" in name:
                        has_remember = True

            # Links for flows and OAuth/SSO hints
            for a in soup.find_all("a"):
                href = (a.get("href") or "").lower()
                text = "".join(a.stripped_strings).lower()
                if "register" in href or "signup" in href or "sign-up" in href or "register" in text:
                    has_register = True
                if "reset" in href or "forgot" in href or "lostpassword" in href or "forgot" in text:
                    has_reset = True
                if "logout" in href or "signout" in href or "sign-out" in href:
                    has_logout = True
                if "oauth" in href or "openid" in href or "sso" in href:
                    if cand.kind == "unknown":
                        cand.kind = "oauth" if "oauth" in href or "openid" in href else "sso"
        except Exception:
            # Fallback to regex heuristics below
            pass

    if not has_form:
        # Very small regex-based form detection if soup failed
        if re.search(r"<form[^>]*>", body, re.IGNORECASE):
            has_form = True
        if re.search(r"type\s*=\s*['\"]password['\"]", body, re.IGNORECASE):
            has_pwd = True

    # Update candidate fields from analysis
    cand.has_form = has_form
    cand.has_password_field = has_pwd
    cand.has_csrf_token_hint = has_csrf
    cand.has_register_hint = has_register
    cand.has_reset_hint = has_reset
    cand.has_logout_hint = has_logout
    cand.has_remember_me_hint = has_remember
    cand.form_action = form_action
    cand.guessed_method = guessed_method

    # If we saw a real HTML form with password, classify as html_form
    if has_form and has_pwd and cand.kind == "unknown":
        cand.kind = "html_form"


def _recompute_confidence(cand: AuthCandidate) -> None:
    """Assign confidence based on structural signals instead of simple additive merging."""
    score = 0
    url_lower = (cand.url or "").lower()

    if cand.has_form and cand.has_password_field:
        score += 60
    elif "login" in url_lower or "signin" in url_lower:
        score += 25

    if cand.kind in {"json_api", "xmlrpc", "oauth", "sso"}:
        score += 20

    if (cand.redirect_target or "").lower().find("login") != -1:
        score += 15

    if cand.has_csrf_token_hint:
        score += 10
    if cand.has_captcha:
        score += 8
    if cand.has_register_hint:
        score += 5
    if cand.has_reset_hint:
        score += 5
    if cand.has_logout_hint:
        score += 5
    if cand.has_remember_me_hint:
        score += 3

    if cand.rate_limit_hints:
        score += 5
    if cand.lockout_hints:
        score += 8

    # Auth/admin buckets without structural signals should remain weak
    if cand.source.startswith("endpoint_analysis_admin_like") and score < 40:
        score = min(score, 30)

    cand.confidence = max(0, min(100, score))


def _build_auth_flows(auth_candidates: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group auth candidates into simple auth flow buckets."""
    flows: dict[str, list[dict[str, Any]]] = {
        "login": [],
        "register": [],
        "reset": [],
        "logout": [],
        "xmlrpc": [],
        "oauth_sso": [],
        "admin_to_login_redirect": [],
    }

    for cand in auth_candidates:
        url = str(cand.get("url") or "")
        final_url = str(cand.get("final_url") or url)
        url_lower = url.lower()
        kind = str(cand.get("kind") or "unknown")

        entry = {
            "url": url,
            "final_url": final_url,
            "kind": kind,
            "confidence": int(cand.get("confidence") or 0),
        }

        if cand.get("has_password_field") or "login" in url_lower or "signin" in url_lower:
            flows["login"].append(entry)
        if cand.get("has_register_hint"):
            flows["register"].append(entry)
        if cand.get("has_reset_hint"):
            flows["reset"].append(entry)
        if cand.get("has_logout_hint"):
            flows["logout"].append(entry)
        if kind == "xmlrpc":
            flows["xmlrpc"].append(entry)
        if kind in {"oauth", "sso"}:
            flows["oauth_sso"].append(entry)

        redirect_target = str(cand.get("redirect_target") or "")
        if redirect_target and "admin" in url_lower and "login" in redirect_target.lower():
            flows["admin_to_login_redirect"].append(
                {
                    "from": url,
                    "to": redirect_target,
                    "confidence": int(cand.get("confidence") or 0),
                }
            )

    return flows


def build_auth_profile(
    checks_results: dict[str, Any] | None,
    endpoint_analysis: dict[str, Any] | None,
) -> dict[str, Any]:
    checks_results = checks_results or {}
    endpoint_analysis = endpoint_analysis or {}

    login_pages = checks_results.get("login_pages", []) or []
    captcha_pages = checks_results.get("captcha_pages", []) or []
    docs_pages = checks_results.get("docs_pages", []) or []
    rate_signals = checks_results.get("rate_limit_signals", []) or []

    reportworthy_buckets = endpoint_analysis.get("reportworthy_endpoints_by_bucket", {}) or {}

    # 1) Seed candidates from existing signals (strong vs weak).
    candidates = _classify_initial_candidates(
        login_pages=login_pages,
        captcha_pages=captcha_pages,
        reportworthy_buckets=reportworthy_buckets,
    )

    # 2) Attach rate-limit hints from existing web checks.
    _attach_rate_limit_hints(candidates, rate_signals)

    # 3) Docs pages only provide hints; they never create standalone strong auth endpoints.
    docs_by_origin: dict[str, list[str]] = {}
    docs_by_host: dict[str, list[str]] = {}
    for item in docs_pages:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "").strip()
        if not url:
            continue
        key = _normalize_url(url)
        docs_by_origin.setdefault(key, []).append(url)
        try:
            parsed = urlparse(url)
            host_key = f"{parsed.scheme or 'http'}://{parsed.netloc}"
            if host_key:
                docs_by_host.setdefault(host_key, []).append(url)
        except Exception:
            continue

    for cand in candidates.values():
        key = _normalize_url(cand.url)
        related_docs = list(docs_by_origin.get(key, []))
        try:
            parsed_cand = urlparse(cand.url)
            host_key = f"{parsed_cand.scheme or 'http'}://{parsed_cand.netloc}"
            related_docs.extend(docs_by_host.get(host_key, []))
        except Exception:
            pass
        interesting_docs = [u for u in related_docs if _has_any_keyword(u, AUTH_KEYWORDS)]
        if interesting_docs:
            notes = list(cand.notes or [])
            # Only keep a few examples to avoid bloating output
            sample = ", ".join(sorted(set(interesting_docs))[:3])
            notes.append(f"docs_auth_hint:{sample}")
            cand.notes = notes

    # 4) Lightweight HTML/API probing for a limited number of strong candidates.
    # Selection strategy: pick a balanced set of flows instead of pure score sort.
    all_cands = list(candidates.values())
    # Pre-score once before selection so we have an initial ordering hint
    for c in all_cands:
        _recompute_confidence(c)

    # Helper to filter by simple predicates
    def _pick_where(pred, pool, limit):
        picked: list[AuthCandidate] = []
        for c in pool:
            if len(picked) >= limit:
                break
            if pred(c):
                picked.append(c)
        return picked

    # Priority buckets
    login_like = _pick_where(
        lambda c: c.has_password_field or "login" in (c.url or "").lower(), all_cands, _MAX_PROBED_CANDIDATES
    )
    remaining = [c for c in all_cands if c not in login_like]

    reset_like = _pick_where(lambda c: c.has_reset_hint, remaining, 5)
    remaining = [c for c in remaining if c not in reset_like]

    register_like = _pick_where(lambda c: c.has_register_hint, remaining, 5)
    remaining = [c for c in remaining if c not in register_like]

    logout_like = _pick_where(lambda c: c.has_logout_hint, remaining, 3)
    remaining = [c for c in remaining if c not in logout_like]

    xmlrpc_like = _pick_where(lambda c: "xmlrpc" in (c.url or "").lower(), remaining, 3)
    remaining = [c for c in remaining if c not in xmlrpc_like]

    oauth_like = _pick_where(
        lambda c: "oauth" in (c.url or "").lower() or "sso" in (c.url or "").lower(),
        remaining,
        3,
    )
    remaining = [c for c in remaining if c not in oauth_like]

    # Admin-like: prefer ones that already look auth-related (URL or existing hints)
    admin_candidates = [c for c in remaining if "admin" in (c.url or "").lower()]
    smart_admin: list[AuthCandidate] = []
    if admin_candidates:
        def _admin_score(c: AuthCandidate) -> int:
            u = (c.url or "").lower()
            score = 0
            if "login" in u or "signin" in u:
                score += 10
            if c.has_password_field:
                score += 8
            if c.has_csrf_token_hint:
                score += 5
            if c.redirect_target:
                score += 5
            return score

        admin_sorted = sorted(
            admin_candidates,
            key=lambda c: (_admin_score(c), int(c.confidence or 0)),
            reverse=True,
        )
        smart_admin = admin_sorted[:4]

    admin_like = smart_admin
    remaining = [c for c in remaining if c not in admin_like]

    # Fill remaining budget by highest confidence
    picked: list[AuthCandidate] = []
    for group in (
        login_like,
        reset_like,
        register_like,
        logout_like,
        xmlrpc_like,
        oauth_like,
        admin_like,
    ):
        for c in group:
            if c not in picked:
                picked.append(c)
                if len(picked) >= _MAX_PROBED_CANDIDATES:
                    break
        if len(picked) >= _MAX_PROBED_CANDIDATES:
            break

    if len(picked) < _MAX_PROBED_CANDIDATES:
        remaining_sorted = sorted(
            remaining,
            key=lambda c: int(c.confidence or 0),
            reverse=True,
        )
        for c in remaining_sorted:
            if c in picked:
                continue
            picked.append(c)
            if len(picked) >= _MAX_PROBED_CANDIDATES:
                break

    to_probe = picked

    session = requests.Session()
    for cand in to_probe:
        _probe_auth_candidate(session, cand)
        _recompute_confidence(cand)

    # 5) Stabilize output list and summary counters.
    # Only keep candidates that point to real auth workflows (no static/admin assets).
    filtered_candidates: list[AuthCandidate] = [
        cand for cand in candidates.values() if _is_auth_workflow_url(cand.url)
    ]
    auth_candidates = sorted(
        [asdict(cand) for cand in filtered_candidates],
        key=lambda c: int(c.get("confidence", 0) or 0),
        reverse=True,
    )[:100]

    summary = {
        "total_candidates": len(auth_candidates),
        "login_form_count": sum(
            1 for c in auth_candidates if c.get("kind") == "html_form"
        ),
        "api_auth_count": sum(
            1 for c in auth_candidates if c.get("kind") == "json_api"
        ),
        "xmlrpc_count": sum(1 for c in auth_candidates if c.get("kind") == "xmlrpc"),
        "oauth_sso_count": sum(
            1 for c in auth_candidates if c.get("kind") in {"oauth", "sso"}
        ),
        "candidates_with_captcha": sum(1 for c in auth_candidates if c.get("has_captcha")),
        "candidates_with_csrf": sum(
            1 for c in auth_candidates if c.get("has_csrf_token_hint")
        ),
        "candidates_with_register": sum(
            1 for c in auth_candidates if c.get("has_register_hint")
        ),
        "candidates_with_reset": sum(
            1 for c in auth_candidates if c.get("has_reset_hint")
        ),
        "candidates_with_logout": sum(
            1 for c in auth_candidates if c.get("has_logout_hint")
        ),
        "candidates_with_remember_me": sum(
            1 for c in auth_candidates if c.get("has_remember_me_hint")
        ),
        "candidates_with_rate_limit_hints": sum(
            1 for c in auth_candidates if c.get("rate_limit_hints")
        ),
        "candidates_with_lockout_hints": sum(
            1 for c in auth_candidates if c.get("lockout_hints")
        ),
    }

    # 6) Canonical scoring summary (deduplicated auth flow families).
    # Families are based on normalized URLs for auth workflows; reset/lostpassword
    # is treated as a subflow, not a separate login family. XML-RPC and OAuth/SSO
    # families are tracked once each.
    login_families: set[str] = set()
    admin_auth_families: set[tuple[str, str]] = set()
    reset_families: set[str] = set()
    xmlrpc_families: set[str] = set()
    oauth_sso_families: set[str] = set()
    hardening_gap_families: set[str] = set()

    for cand in filtered_candidates:
        norm = _normalize_url(cand.url)
        if not norm:
            continue

        # Login family: real HTML form + password field, or explicit login path.
        is_login_family = False
        if cand.has_form and cand.has_password_field:
            is_login_family = True
        else:
            lower_url = (cand.url or "").lower()
            if "login" in lower_url or "signin" in lower_url or "sign-in" in lower_url:
                is_login_family = True

        # Reset subflow: lostpassword/reset/forgot markers.
        lower_url = (cand.url or "").lower()
        is_reset_subflow = any(
            m in lower_url for m in ("lostpassword", "reset", "forgot")
        )

        if is_login_family and not is_reset_subflow:
            login_families.add(norm)
            # Hardening gaps are only meaningful on real login flows.
            if (
                not cand.has_captcha
                or not cand.has_csrf_token_hint
                or not (cand.rate_limit_hints or cand.lockout_hints)
            ):
                hardening_gap_families.add(norm)
        elif is_reset_subflow:
            reset_families.add(norm)

        # XML-RPC family
        if "xmlrpc" in lower_url:
            xmlrpc_families.add(_normalize_url(cand.url))

        # OAuth/SSO family
        if "oauth" in lower_url or "sso" in lower_url or "openid" in lower_url:
            oauth_sso_families.add(_normalize_url(cand.url))

        # Admin → login redirect families are computed from flows below.

    # Admin → login redirect families from auth_flows
    admin_redirects = (auth_flows or {}).get("admin_to_login_redirect") or []
    if isinstance(admin_redirects, list):
        for item in admin_redirects:
            if not isinstance(item, dict):
                continue
            frm = str(item.get("from") or "").strip()
            to = str(item.get("to") or "").strip()
            if not frm or not to:
                continue
            norm_from = _normalize_url(frm)
            norm_to = _normalize_url(to)
            if norm_from and norm_to:
                admin_auth_families.add((norm_from, norm_to))

    auth_scoring_summary = {
        "canonical_login_flows_count": len(login_families),
        "canonical_admin_auth_flows_count": len(admin_auth_families),
        "canonical_reset_flows_count": len(reset_families),
        "canonical_xmlrpc_count": len(xmlrpc_families),
        "canonical_oauth_sso_count": len(oauth_sso_families),
        "hardening_gaps_on_real_login_flows_count": len(hardening_gap_families),
    }

    auth_flows = _build_auth_flows(auth_candidates)

    return {
        "auth_candidates": auth_candidates,
        "auth_summary": summary,
        "auth_flows": auth_flows,
        "auth_scoring_summary": auth_scoring_summary,
    }


