"""List-compatible scanner evidence with explicit execution diagnostics."""
from __future__ import annotations

from typing import Any, Iterable


class ScannerItems(list):
    def __init__(self, items: Iterable = (), *, returncode: int = 0, error: str = ""):
        super().__init__(items)
        self.returncode = returncode
        self.error = error or (f"scanner failed rc={returncode}" if returncode else "")


def scanner_metadata(result: Any) -> dict[str, Any]:
    if isinstance(result, dict):
        code = result.get("returncode")
        error = str(result.get("error") or result.get("stderr") or "") if code not in (None, 0) or result.get("error") else ""
        items = result.get("findings") or result.get("urls") or []
    else:
        code = getattr(result, "returncode", 0)
        error = str(getattr(result, "error", "") or "")
        items = result
    failed = bool(error) or code not in (None, 0)
    if failed and not error:
        error = f"scanner failed rc={code}"
    return {"status": ("partial" if items else "error") if failed else "done", "returncode": code, "error": error or None}


def aggregate_scanner_status(records: list[dict[str, Any]]) -> tuple[str, str | None]:
    failed = [row for row in records if row.get("status") in {"error", "partial"}]
    if not failed:
        return "done", None
    status = "error" if all(row.get("status") == "error" for row in records) else "partial"
    return status, "; ".join(str(row.get("error") or "scanner failed") for row in failed[:3])
