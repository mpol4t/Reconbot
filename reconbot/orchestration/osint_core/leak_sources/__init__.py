"""Safe metadata-only leak-source collector contracts.

This package contains metadata-only collectors. It does not perform Tor access,
onion crawling, darkweb forum scraping, credential validation, dump downloads,
raw paste collection, or secret storage.
"""

from __future__ import annotations

from .collector_contract import LeakSourceCollector, build_disabled_result, build_manual_review_health_row
from .metadata_feed import result_from_metadata_feed
from .models import LeakSourceReference, LeakSourceResult, SuppressedSensitiveItem
from .policy import LEAK_SOURCE_CLASSIFICATIONS, SAFETY_BOUNDARY, sanitize_reference_payload
from .redaction import redact_email, redact_phone, redact_text

__all__ = [
    "LEAK_SOURCE_CLASSIFICATIONS",
    "SAFETY_BOUNDARY",
    "LeakSourceCollector",
    "LeakSourceReference",
    "LeakSourceResult",
    "SuppressedSensitiveItem",
    "build_disabled_result",
    "build_manual_review_health_row",
    "result_from_metadata_feed",
    "redact_email",
    "redact_phone",
    "redact_text",
    "sanitize_reference_payload",
]
