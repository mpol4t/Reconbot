"""Runtime dependency inventory and preflight checks."""

from __future__ import annotations

import importlib
import platform
import sys
from dataclasses import dataclass
from typing import Callable


INSTALL_COMMAND = "python3 -m pip install -r requirements.txt"


@dataclass(frozen=True)
class RuntimeDependency:
    name: str
    import_name: str


@dataclass(frozen=True)
class DependencyStatus:
    name: str
    import_name: str
    ok: bool
    error: str = ""


REQUIRED_RUNTIME_DEPENDENCIES: tuple[RuntimeDependency, ...] = (
    RuntimeDependency("requests", "requests"),
    RuntimeDependency("tldextract", "tldextract"),
    RuntimeDependency("dnspython", "dns.resolver"),
    RuntimeDependency("PySide6", "PySide6"),
)


ImportFunc = Callable[[str], object]


def runtime_diagnostic(import_func: ImportFunc | None = None) -> dict[str, object]:
    importer = import_func or importlib.import_module
    dependencies: list[dict[str, object]] = []
    for dependency in REQUIRED_RUNTIME_DEPENDENCIES:
        # The frozen Electron backend has no Qt interface; developer/legacy
        # Python app preflight continues to require PySide6.
        if getattr(sys, "frozen", False) and dependency.name == "PySide6":
            continue
        try:
            importer(dependency.import_name)
        except Exception as exc:
            dependencies.append(
                {
                    "name": dependency.name,
                    "import_name": dependency.import_name,
                    "ok": False,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            continue
        dependencies.append(
            {
                "name": dependency.name,
                "import_name": dependency.import_name,
                "ok": True,
                "error": "",
            }
        )
    return {
        "python_executable": sys.executable,
        "python_version": platform.python_version(),
        "sys_path_excerpt": [str(item) for item in sys.path[:8]],
        "dependencies": dependencies,
    }


def dependency_statuses(import_func: ImportFunc | None = None) -> list[DependencyStatus]:
    diagnostic = runtime_diagnostic(import_func=import_func)
    statuses: list[DependencyStatus] = []
    for item in diagnostic["dependencies"]:
        if not isinstance(item, dict):
            continue
        statuses.append(
            DependencyStatus(
                name=str(item.get("name") or ""),
                import_name=str(item.get("import_name") or ""),
                ok=bool(item.get("ok")),
                error=str(item.get("error") or ""),
            )
        )
    return statuses


def missing_dependencies(import_func: ImportFunc | None = None) -> list[DependencyStatus]:
    return [status for status in dependency_statuses(import_func=import_func) if not status.ok]


def friendly_missing_dependency_message(status: DependencyStatus) -> str:
    return f"Missing Python dependency: {status.name}. Run: {INSTALL_COMMAND}"


def format_runtime_check(import_func: ImportFunc | None = None) -> tuple[bool, str]:
    diagnostic = runtime_diagnostic(import_func=import_func)
    lines = [
        f"Python executable: {diagnostic['python_executable']}",
        f"Python version: {diagnostic['python_version']}",
        "sys.path excerpt:",
    ]
    for item in diagnostic["sys_path_excerpt"]:
        lines.append(f"  - {item}")
    lines.append("Required dependencies:")
    all_ok = True
    for item in diagnostic["dependencies"]:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        import_name = str(item.get("import_name") or "")
        ok = bool(item.get("ok"))
        error = str(item.get("error") or "")
        if ok:
            lines.append(f"  - {name} ({import_name}): OK")
        else:
            all_ok = False
            lines.append(f"  - {name} ({import_name}): FAIL - {error}")
            lines.append(f"    {friendly_missing_dependency_message(DependencyStatus(name, import_name, False, error))}")
    return all_ok, "\n".join(lines)


def runtime_preflight_error(import_func: ImportFunc | None = None) -> str:
    missing = missing_dependencies(import_func=import_func)
    if not missing:
        return ""
    lines = [friendly_missing_dependency_message(status) for status in missing]
    return "\n".join(lines)
