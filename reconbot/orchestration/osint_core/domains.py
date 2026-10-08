"""Offline Public Suffix List based organization boundaries for all collectors."""
from __future__ import annotations

import ipaddress
import re
from functools import lru_cache
from urllib.parse import urlsplit

import tldextract

# Use the package's snapshot: never fetch or write a cache during a scan.
_extract = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=(), include_psl_private_domains=True)


@lru_cache(maxsize=8192)
def registered_domain(value: str) -> str:
    raw = str(value or "").strip().lower().replace("*.", "")
    host = ""
    try:
        host = (urlsplit(raw if "://" in raw else "//" + raw).hostname or "").strip(".")
        host = host.encode("idna").decode("ascii")
        ipaddress.ip_address(host)
        return ""
    except ValueError:
        pass
    except UnicodeError:
        return ""
    if not host or not re.fullmatch(r"[a-z0-9.-]+", host) or any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in host.split(".")):
        return ""
    result = _extract(host)
    if result.suffix:
        return result.top_domain_under_public_suffix or ""
    # Keep explicit local/test/custom suffix behavior without inventing a PSL boundary.
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else ""
