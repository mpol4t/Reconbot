from __future__ import annotations

import os
import sys

from reconbot.core.checks import preflight_check
from reconbot.orchestration.cli_parser import build_parser
from reconbot.report.builder import generate_report
from reconbot.runtime.dependencies import format_runtime_check, runtime_preflight_error


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if getattr(args, "check_runtime", False):
        ok, output = format_runtime_check()
        print(output, flush=True)
        raise SystemExit(0 if ok else 1)
    if not str(getattr(args, "target", "") or "").strip():
        parser.error("target is required unless --check-runtime is used")
    target_text = str(getattr(args, "target", "") or "").strip().lower()
    app_commands = {"app", "gui", "dashboard"}
    if target_text not in app_commands:
        runtime_error = runtime_preflight_error()
        if runtime_error:
            print(runtime_error, file=sys.stderr, flush=True)
            raise SystemExit(1)
    from reconbot.orchestration.runner import run_from_parsed_args

    run_from_parsed_args(args)


__all__ = ["main", "generate_report"]


if __name__ == "__main__":
    main()
