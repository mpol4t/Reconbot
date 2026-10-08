"""The frozen CLI backend must not require a second desktop GUI toolkit."""
import sys
from unittest.mock import patch

from reconbot.runtime.dependencies import runtime_diagnostic


def test_frozen_backend_preflight_works_without_qt_but_still_requires_scanner_dependencies():
    def importer(name):
        if name in {"PySide6", "requests"}:
            raise ImportError(name)
        return object()

    with patch.object(sys, "frozen", True, create=True):
        frozen = runtime_diagnostic(importer)
    statuses = {item["name"]: item["ok"] for item in frozen["dependencies"]}
    assert "PySide6" not in statuses
    assert statuses["requests"] is False
    assert statuses["dnspython"] is True
    with patch.object(sys, "frozen", False, create=True):
        legacy = runtime_diagnostic(importer)
    assert any(item["name"] == "PySide6" and not item["ok"] for item in legacy["dependencies"])
