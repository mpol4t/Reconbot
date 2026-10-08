"""Stable OSINT orchestration facade.

The implementation lives under :mod:`reconbot.orchestration.osint_core`.
This module intentionally remains import-compatible for the app, tests, and
existing monkeypatch paths such as ``reconbot.orchestration.osint._fetch_json``.
"""

from __future__ import annotations

import sys

from reconbot.orchestration.osint_core import pipeline as _pipeline

sys.modules[__name__] = _pipeline
