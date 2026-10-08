from __future__ import annotations

import json
import os
import signal
import shlex
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


_TOOL_ORDER: list[tuple[str, str]] = [
    ("nmap", "Nmap"),
    ("subfinder", "Subfinder"),
    ("dnsx", "DNSX"),
    ("httpx", "HTTPX"),
    ("katana", "Katana"),
    ("gobuster", "Gobuster"),
    ("ffuf", "FFUF"),
    ("historical_urls", "Historical"),
    ("wafw00f", "WAFW00F"),
    ("whatweb", "WhatWeb"),
    ("checks", "Web Checks"),
    ("screenshots", "Screenshots"),
    ("nuclei", "Nuclei"),
]


_DEFAULT_TOOL_ENABLED: dict[str, bool] = {
    "nmap": True,
    "subfinder": True,
    "dnsx": True,
    "httpx": True,
    "katana": True,
    "gobuster": True,
    "ffuf": False,
    "historical_urls": False,
    "wafw00f": True,
    "whatweb": True,
    "checks": True,
    "screenshots": False,
    "nuclei": True,
}


def _safe_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        low = value.strip().lower()
        if low in {"1", "true", "yes", "on"}:
            return True
        if low in {"0", "false", "no", "off"}:
            return False
    return default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _read_json(path: Path) -> dict[str, Any]:
    try:
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}
    return {}


def _tail_lines(path: Path, limit: int = 80) -> list[str]:
    try:
        if not path.exists():
            return []
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        return lines[-limit:]
    except Exception:
        return []


def _is_url_target(target: str) -> bool:
    target_text = str(target or "").strip().lower()
    return target_text.startswith("http://") or target_text.startswith("https://")


def _auto_skipped_tools_for_target(target: str, selected_tools: dict[str, bool]) -> dict[str, str]:
    if not _is_url_target(target):
        return {}
    reason = "auto-skipped: URL target mode"
    return {name: reason for name in ("subfinder", "dnsx", "httpx") if selected_tools.get(name)}


def _base_output_dir(raw_output_dir: str | None) -> Path:
    if raw_output_dir:
        app_root = Path(raw_output_dir).expanduser().resolve()
    else:
        app_root = (Path(__file__).resolve().parents[1] / "output").resolve()
    if app_root.name.lower() == "latest":
        app_root = app_root.parent
    app_root.mkdir(parents=True, exist_ok=True)
    return app_root


def _tool_field_name(name: str) -> str:
    return "screenshots_enable" if name == "screenshots" else f"{name}_enabled"


def _app_defaults_from_config(config_defaults: dict[str, Any] | None, base_output_dir: str | None) -> dict[str, Any]:
    cfg = config_defaults or {}
    selected_tools: dict[str, bool] = {}
    for name, _label in _TOOL_ORDER:
        selected_tools[name] = _safe_bool(cfg.get(_tool_field_name(name)), _DEFAULT_TOOL_ENABLED.get(name, True))
    return {
        "target": str(cfg.get("target") or ""),
        "wordlist": str(cfg.get("wordlist") or ""),
        "output_dir": str(base_output_dir or cfg.get("output_dir") or ""),
        "traffic_profile": str(cfg.get("traffic_profile") or "balanced"),
        "report_depth": str(cfg.get("report_depth") or "balanced"),
        "tools": selected_tools,
    }


def _write_app_config(path: Path, payload: dict[str, Any], output_base_dir: Path) -> None:
    tools = payload.get("tools") if isinstance(payload.get("tools"), dict) else {}
    reconbot_cfg: dict[str, Any] = {
        "wordlist": str(payload.get("wordlist") or "").strip(),
        "output_dir": str(output_base_dir),
        "verbose": True,
        "traffic_profile": str(payload.get("traffic_profile") or "balanced"),
        "report_depth": str(payload.get("report_depth") or "balanced"),
    }
    for name, _label in _TOOL_ORDER:
        reconbot_cfg[_tool_field_name(name)] = _safe_bool(tools.get(name), _DEFAULT_TOOL_ENABLED.get(name, True))
    path.write_text(json.dumps({"reconbot": reconbot_cfg}, ensure_ascii=False, indent=2), encoding="utf-8")


def _truncate_line(line: str, limit: int = 1400) -> str:
    text = str(line or "")
    if len(text) <= limit:
        return text
    return f"{text[:limit]} ... [truncated, open raw log for full line]"


def _stage_label(name: str) -> str:
    for tool_name, label in _TOOL_ORDER:
        if tool_name == name:
            return label
    return name.replace("_", " ").title()


def _tool_metric(name: str, summary: dict[str, Any], stage: dict[str, Any]) -> str:
    if name == "katana":
        return f"{_safe_int(summary.get('katana_count'))} urls"
    if name == "gobuster":
        return f"{_safe_int(summary.get('gobuster_total_hits'))} hits"
    if name == "ffuf":
        return f"{_safe_int(summary.get('ffuf_hits'))} hits"
    if name == "historical_urls":
        return f"{_safe_int(summary.get('historical_live_count'))} live"
    if name == "screenshots":
        return f"{_safe_int(summary.get('screenshots_captured_count'))} files"
    if name == "checks":
        return f"{_safe_int(summary.get('checks_checked'))} checked"
    if name == "nuclei":
        if stage.get("findings_count") is not None:
            return f"{_safe_int(stage.get('findings_count'))} findings"
        return f"{_safe_int(summary.get('nuclei_findings_count'))} findings"
    artifacts = stage.get("artifacts") if isinstance(stage.get("artifacts"), dict) else {}
    if artifacts:
        return f"{len(artifacts)} artifacts"
    return "ready"


def _normalize_skipped(run_result: dict[str, Any]) -> set[str]:
    skipped: set[str] = set()
    for source in (
        run_result.get("skipped_tools"),
        (run_result.get("meta") if isinstance(run_result.get("meta"), dict) else {}).get("skipped_tools"),
    ):
        if isinstance(source, list):
            skipped.update(str(item) for item in source if str(item or "").strip())
    return skipped


def _findings_from_jsonl(run_dir: Path, run_result: dict[str, Any]) -> list[dict[str, str]]:
    nuclei = run_result.get("nuclei") if isinstance(run_result.get("nuclei"), dict) else {}
    candidates: list[Path] = []
    output_path = nuclei.get("output_path") if isinstance(nuclei, dict) else None
    if output_path:
        candidates.append(Path(str(output_path)))
    candidates.append(run_dir / "nuclei_output.jsonl")
    jsonl_path = next((path for path in candidates if path.exists()), None)
    if jsonl_path is None:
        return []

    findings: list[dict[str, str]] = []
    for raw_line in _tail_lines(jsonl_path, limit=100):
        line = raw_line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except Exception:
            continue
        if not isinstance(item, dict):
            continue
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        findings.append(
            {
                "name": str(info.get("name") or item.get("template-id") or "Unknown"),
                "severity": str(info.get("severity") or "unknown"),
                "template_id": str(item.get("template-id") or "Unknown"),
                "matched_at": str(item.get("matched-at") or item.get("host") or item.get("url") or ""),
            }
        )
    return findings[-30:]


def start_desktop_app(
    *,
    base_output_dir: str | None = None,
    config_defaults: dict[str, Any] | None = None,
    project_root: Path | None = None,
) -> int:
    try:
        from PySide6.QtCore import QEvent, QProcess, QProcessEnvironment, QTimer, Qt, QUrl
        from PySide6.QtGui import QColor, QDesktopServices, QKeyEvent, QPalette
        from PySide6.QtWidgets import (
            QApplication,
            QButtonGroup,
            QCheckBox,
            QComboBox,
            QFrame,
            QGridLayout,
            QGroupBox,
            QHBoxLayout,
            QLabel,
            QLineEdit,
            QListWidget,
            QListWidgetItem,
            QMainWindow,
            QMessageBox,
            QPushButton,
            QPlainTextEdit,
            QRadioButton,
            QScrollArea,
            QSizePolicy,
            QSplitter,
            QTableWidget,
            QTableWidgetItem,
            QVBoxLayout,
            QWidget,
        )
    except ImportError:
        print("[!] PySide6 bulunamadı. Desktop app için dependency ekleyin: pip install PySide6", flush=True)
        return 1

    app_root = _base_output_dir(base_output_dir or (config_defaults or {}).get("output_dir"))
    defaults = _app_defaults_from_config(config_defaults, str(app_root))
    project_root = project_root or Path(__file__).resolve().parents[2]

    class ReconBotOperatorConsole(QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self.setWindowTitle("ReconBot Operator Console")
            self.resize(1480, 900)
            self.app_root = app_root
            self.defaults = defaults
            self.project_root = Path(project_root).resolve()
            self.process: QProcess | None = None
            self.request_dir: Path | None = None
            self.current_run_dir: Path | None = None
            self.startup_log_lines: list[str] = []
            self.selected_tools: dict[str, bool] = dict(defaults.get("tools") or {})
            self.auto_skipped_tools: dict[str, str] = {}
            self.run_result: dict[str, Any] = {}
            self.live_stages: dict[str, Any] = {}
            self.report_mtime = 0.0
            self._build_ui()
            self._apply_style()
            self._load_defaults()
            app_instance = QApplication.instance()
            if app_instance is not None:
                app_instance.installEventFilter(self)
            self.poll_timer = QTimer(self)
            self.poll_timer.timeout.connect(self._refresh_state)
            self.poll_timer.start(1500)

        def _build_ui(self) -> None:
            root = QWidget()
            root_layout = QHBoxLayout(root)
            root_layout.setContentsMargins(14, 14, 14, 14)
            root_layout.setSpacing(12)

            splitter = QSplitter(Qt.Horizontal)
            splitter.addWidget(self._build_left_panel())
            splitter.addWidget(self._build_center_panel())
            splitter.addWidget(self._build_right_panel())
            splitter.setSizes([330, 760, 390])
            root_layout.addWidget(splitter)
            self.setCentralWidget(root)

        def _build_left_panel(self) -> QWidget:
            panel = QWidget()
            layout = QVBoxLayout(panel)
            layout.setSpacing(12)

            title = QLabel("ReconBot Operator Console")
            title.setObjectName("Title")
            subtitle = QLabel("Desktop scan control")
            subtitle.setObjectName("Muted")
            layout.addWidget(title)
            layout.addWidget(subtitle)

            setup = QGroupBox("Setup")
            form = QVBoxLayout(setup)
            self.target_input = QLineEdit()
            self.target_input.setPlaceholderText("https://target.local or domain")
            self.wordlist_input = QLineEdit()
            self.wordlist_input.setPlaceholderText("Wordlist path")
            form.addWidget(QLabel("Target"))
            form.addWidget(self.target_input)
            form.addWidget(QLabel("Wordlist"))
            form.addWidget(self.wordlist_input)

            form.addWidget(QLabel("Traffic profile"))
            self.profile_group = QButtonGroup(self)
            self.profile_buttons: dict[str, QRadioButton] = {}
            profile_row = QHBoxLayout()
            for value, label in (("safe", "Safe"), ("balanced", "Balanced"), ("fast", "Fast")):
                button = QRadioButton(label)
                self.profile_group.addButton(button)
                self.profile_buttons[value] = button
                profile_row.addWidget(button)
            form.addLayout(profile_row)

            form.addWidget(QLabel("Report depth"))
            self.report_depth_select = QComboBox()
            self.report_depth_select.addItems(["summary", "balanced", "deep"])
            form.addWidget(self.report_depth_select)

            action_row = QHBoxLayout()
            self.start_button = QPushButton("Start Scan")
            self.start_button.setObjectName("StartButton")
            self.stop_button = QPushButton("Stop")
            self.stop_button.setEnabled(False)
            self.start_button.clicked.connect(self._start_scan)
            self.stop_button.clicked.connect(lambda: self._stop_scan("button"))
            action_row.addWidget(self.start_button, 2)
            action_row.addWidget(self.stop_button, 1)
            form.addLayout(action_row)
            self.status_label = QLabel("Ready")
            self.status_label.setObjectName("Muted")
            form.addWidget(self.status_label)
            layout.addWidget(setup)

            tools_box = QGroupBox("Tools")
            tools_layout = QVBoxLayout(tools_box)
            self.tool_checks: dict[str, QCheckBox] = {}
            for name, label in _TOOL_ORDER:
                check = QCheckBox(label)
                self.tool_checks[name] = check
                tools_layout.addWidget(check)
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setWidget(tools_box)
            layout.addWidget(scroll, 1)
            return panel

        def _build_center_panel(self) -> QWidget:
            panel = QWidget()
            layout = QVBoxLayout(panel)
            layout.setSpacing(12)

            metrics = QFrame()
            metrics.setObjectName("Card")
            metrics_layout = QGridLayout(metrics)
            self.metric_labels: dict[str, QLabel] = {}
            for idx, key in enumerate(("Run", "Katana", "Gobuster", "FFUF", "Nuclei", "Report")):
                label = QLabel("0")
                label.setObjectName("MetricValue")
                caption = QLabel(key)
                caption.setObjectName("Muted")
                cell = QWidget()
                cell_layout = QVBoxLayout(cell)
                cell_layout.setContentsMargins(8, 8, 8, 8)
                cell_layout.addWidget(label)
                cell_layout.addWidget(caption)
                metrics_layout.addWidget(cell, 0, idx)
                self.metric_labels[key] = label
            layout.addWidget(metrics)

            self.stage_table = QTableWidget(0, 4)
            self.stage_table.setHorizontalHeaderLabels(["Tool", "Status", "Metric", "Reason"])
            self.stage_table.verticalHeader().setVisible(False)
            self.stage_table.horizontalHeader().setStretchLastSection(True)
            self.stage_table.setEditTriggers(QTableWidget.NoEditTriggers)
            self.stage_table.setSelectionBehavior(QTableWidget.SelectRows)
            layout.addWidget(self.stage_table, 2)

            self.console = QPlainTextEdit()
            self.console.setReadOnly(True)
            self.console.setObjectName("Console")
            self.console.setPlaceholderText("Live scan output")
            self.console.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
            layout.addWidget(self.console, 3)
            return panel

        def _build_right_panel(self) -> QWidget:
            panel = QWidget()
            layout = QVBoxLayout(panel)
            layout.setSpacing(12)

            summary_box = QGroupBox("Run Summary")
            summary_layout = QVBoxLayout(summary_box)
            self.summary_label = QLabel("No run yet")
            self.summary_label.setWordWrap(True)
            summary_layout.addWidget(self.summary_label)
            layout.addWidget(summary_box)

            artifact_box = QGroupBox("Artifacts")
            artifact_layout = QVBoxLayout(artifact_box)
            self.open_report_button = QPushButton("Open Report")
            self.open_run_folder_button = QPushButton("Open Run Folder")
            self.open_raw_log_button = QPushButton("Open Raw Log")
            self.open_state_json_button = QPushButton("Open State JSON")
            self.open_report_button.clicked.connect(lambda: self._open_artifact("report.html"))
            self.open_run_folder_button.clicked.connect(self._open_run_folder)
            self.open_raw_log_button.clicked.connect(lambda: self._open_artifact("reconbot.log"))
            self.open_state_json_button.clicked.connect(lambda: self._open_artifact("run_result.json"))
            for button in (
                self.open_report_button,
                self.open_run_folder_button,
                self.open_raw_log_button,
                self.open_state_json_button,
            ):
                artifact_layout.addWidget(button)
            layout.addWidget(artifact_box)

            findings_box = QGroupBox("Live Findings")
            findings_layout = QVBoxLayout(findings_box)
            self.findings_list = QListWidget()
            findings_layout.addWidget(self.findings_list)
            layout.addWidget(findings_box, 1)
            return panel

        def _apply_style(self) -> None:
            self.setStyleSheet(
                """
                QMainWindow, QWidget { background: #0b0c0a; color: #f2f4e8; font-size: 13px; }
                QGroupBox { border: 1px solid #303326; border-radius: 8px; margin-top: 10px; padding: 12px; background: #141511; }
                QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 4px; color: #d8ff5f; }
                QLineEdit, QComboBox, QPlainTextEdit, QTableWidget, QListWidget { background: #10120e; color: #f2f4e8; border: 1px solid #303326; border-radius: 7px; padding: 6px; selection-background-color: #536122; }
                QPushButton { background: #191b16; color: #f2f4e8; border: 1px solid #303326; border-radius: 7px; padding: 8px 10px; }
                QPushButton:hover { border-color: #d8ff5f; }
                QPushButton:disabled { color: #737866; border-color: #24271e; }
                QPushButton#StartButton { background: #d8ff5f; color: #141511; font-weight: 700; }
                QCheckBox, QRadioButton { spacing: 8px; }
                QLabel#Title { font-size: 24px; font-weight: 700; }
                QLabel#Muted { color: #a9ad9b; }
                QLabel#MetricValue { font-size: 22px; font-weight: 700; color: #d8ff5f; }
                QFrame#Card { background: #141511; border: 1px solid #303326; border-radius: 8px; }
                QPlainTextEdit#Console { font-family: Menlo, Consolas, monospace; font-size: 12px; }
                QHeaderView::section { background: #191b16; color: #a9ad9b; border: 0; padding: 6px; }
                """
            )
            palette = self.palette()
            palette.setColor(QPalette.Window, QColor("#0b0c0a"))
            self.setPalette(palette)

        def _load_defaults(self) -> None:
            self.target_input.setText(str(self.defaults.get("target") or ""))
            self.wordlist_input.setText(str(self.defaults.get("wordlist") or ""))
            profile = str(self.defaults.get("traffic_profile") or "balanced").lower()
            self.profile_buttons.get(profile, self.profile_buttons["balanced"]).setChecked(True)
            depth = str(self.defaults.get("report_depth") or "balanced").lower()
            index = self.report_depth_select.findText(depth)
            self.report_depth_select.setCurrentIndex(index if index >= 0 else 1)
            for name, check in self.tool_checks.items():
                check.setChecked(bool(self.selected_tools.get(name, _DEFAULT_TOOL_ENABLED.get(name, True))))
            self._render_tool_table({})
            self._update_artifact_buttons()

        def _selected_profile(self) -> str:
            for value, button in self.profile_buttons.items():
                if button.isChecked():
                    return value
            return "balanced"

        def _selected_payload(self) -> dict[str, Any]:
            tools = {name: check.isChecked() for name, check in self.tool_checks.items()}
            return {
                "target": self.target_input.text().strip(),
                "wordlist": self.wordlist_input.text().strip(),
                "traffic_profile": self._selected_profile(),
                "report_depth": self.report_depth_select.currentText(),
                "tools": tools,
            }

        def _append_console(self, line: str) -> None:
            text = _truncate_line(line.rstrip("\n"))
            scrollbar = self.console.verticalScrollBar()
            was_at_bottom = scrollbar.value() >= scrollbar.maximum() - 8
            self.console.appendPlainText(text)
            if was_at_bottom:
                scrollbar.setValue(scrollbar.maximum())

        def _append_app_log(self, message: str) -> None:
            target_dir = self.current_run_dir or self.request_dir
            if target_dir is None:
                return
            try:
                target_dir.mkdir(parents=True, exist_ok=True)
                stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with (target_dir / "reconbot.log").open("a", encoding="utf-8") as handle:
                    handle.write(f"{stamp} {message}\n")
            except Exception:
                pass

        def _start_scan(self) -> None:
            payload = self._selected_payload()
            target = str(payload.get("target") or "").strip()
            wordlist = str(payload.get("wordlist") or "").strip()
            tools = payload.get("tools") if isinstance(payload.get("tools"), dict) else {}
            if not target:
                self.status_label.setText("Target zorunlu.")
                QMessageBox.warning(self, "Missing target", "Target zorunlu.")
                return
            if (tools.get("gobuster", True) or tools.get("ffuf", False)) and not wordlist:
                message = "wordlist required because Gobuster/FFUF enabled"
                self.status_label.setText(message)
                QMessageBox.warning(self, "Missing wordlist", message)
                return
            if self.process is not None and self.process.state() != QProcess.NotRunning:
                self.status_label.setText("Zaten çalışan bir scan var.")
                return

            request_id = datetime.now().strftime("%Y%m%d-%H%M%S")
            self.request_dir = (self.app_root / "app_requests" / request_id).resolve()
            self.request_dir.mkdir(parents=True, exist_ok=True)
            self.current_run_dir = self.request_dir
            config_path = self.request_dir / "app_config.yaml"
            _write_app_config(config_path, payload, self.app_root)

            self.selected_tools = {name: bool(tools.get(name, _DEFAULT_TOOL_ENABLED.get(name, True))) for name, _label in _TOOL_ORDER}
            self.auto_skipped_tools = _auto_skipped_tools_for_target(target, self.selected_tools)
            enabled_tools = ", ".join(name for name, enabled in self.selected_tools.items() if enabled) or "-"
            auto_skips = ", ".join(f"{name} ({reason})" for name, reason in self.auto_skipped_tools.items()) or "-"
            cmd = [sys.executable, "-u", "-m", "reconbot", target, "-c", str(config_path)]
            self.startup_log_lines = [
                f"[+] App scan requested: target={target}",
                f"[+] App selected traffic profile: {payload.get('traffic_profile') or 'balanced'}",
                f"[+] App enabled tools: {enabled_tools}",
                f"[+] App auto-skipped tools: {auto_skips}",
                f"[+] Child config: {config_path}",
                f"[+] Child command: {shlex.join(cmd)}",
            ]
            self.console.clear()
            for line in self.startup_log_lines:
                self._append_console(line)
                self._append_app_log(line)

            process = QProcess(self)
            env = QProcessEnvironment.systemEnvironment()
            env.insert("RECONBOT_SKIP_PREFLIGHT", "1")
            env.insert("PYTHONUNBUFFERED", "1")
            process.setProcessEnvironment(env)
            process.setWorkingDirectory(str(self.project_root))
            process.setProgram(cmd[0])
            process.setArguments(cmd[1:])
            process.readyReadStandardOutput.connect(self._read_stdout)
            process.readyReadStandardError.connect(self._read_stderr)
            process.finished.connect(self._process_finished)
            process.errorOccurred.connect(self._process_error)
            self.process = process
            process.start()
            if not process.waitForStarted(3000):
                err = process.errorString()
                self.status_label.setText(f"Scan başlatılamadı: {err}")
                self._append_console(f"[!] Scan start failed: {err}")
                self._append_app_log(f"[!] Scan start failed: {err}")
                self.process = None
                self.current_run_dir = self.request_dir
                self.start_button.setEnabled(True)
                self.stop_button.setEnabled(False)
                return
            pid_log = f"[+] Child PID: {int(process.processId())}"
            self.startup_log_lines.append(pid_log)
            self._append_console(pid_log)
            self._append_app_log(pid_log)
            self.status_label.setText("Scan çalışıyor.")
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self._render_tool_table({})
            self._update_artifact_buttons()

        def _read_stdout(self) -> None:
            self._read_process_channel(False)

        def _read_stderr(self) -> None:
            self._read_process_channel(True)

        def _read_process_channel(self, stderr: bool) -> None:
            if self.process is None:
                return
            raw = self.process.readAllStandardError() if stderr else self.process.readAllStandardOutput()
            text = bytes(raw).decode("utf-8", errors="replace")
            for line in text.splitlines():
                if not line:
                    continue
                prefix = "[stderr] " if stderr else ""
                full_line = f"{prefix}{line}"
                self._append_console(full_line)
                self._append_app_log(full_line)
                marker = "[+] Output (run):"
                if marker in line:
                    self._adopt_run_dir(line.split(marker, 1)[1])

        def _adopt_run_dir(self, candidate: str) -> None:
            try:
                real_run_dir = Path(str(candidate or "").strip()).expanduser().resolve()
                real_run_dir.mkdir(parents=True, exist_ok=True)
            except Exception as exc:
                self._append_console(f"[!] Output run path parse failed: {exc}")
                return
            if self.current_run_dir == real_run_dir:
                return
            old_log_dir = self.current_run_dir
            self.current_run_dir = real_run_dir
            for line in self.startup_log_lines:
                self._append_app_log(line)
            if old_log_dir is not None and old_log_dir != real_run_dir:
                for line in _tail_lines(old_log_dir / "reconbot.log", limit=80):
                    self._append_app_log(line)
            follow_line = f"[+] Desktop app now following run dir: {real_run_dir}"
            self._append_console(follow_line)
            self._append_app_log(follow_line)
            self._update_artifact_buttons()

        def _process_finished(self, exit_code: int, _exit_status: Any) -> None:
            message = f"[+] Child return code: {exit_code}"
            self._append_console(message)
            self._append_app_log(message)
            self.status_label.setText(f"Scan tamamlandı (exit={exit_code})." if exit_code == 0 else f"Scan bitti (exit={exit_code}).")
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self._refresh_state()

        def _process_error(self, _error: Any) -> None:
            if self.process is None:
                return
            message = f"[!] Process error: {self.process.errorString()}"
            self._append_console(message)
            self._append_app_log(message)
            self.status_label.setText(message)

        def _stop_scan(self, source: str) -> None:
            if self.process is None or self.process.state() == QProcess.NotRunning:
                self._append_console("[!] No running scan")
                self.status_label.setText("No running scan")
                return
            message = "[!] Stop requested from console shortcut" if source == "console shortcut" else "[!] Stop requested from GUI stop button"
            self._append_console(message)
            self._append_app_log(message)
            self.process.terminate()
            QTimer.singleShot(5000, self._kill_if_still_running)
            self.status_label.setText("Stop isteği gönderildi.")

        def _kill_if_still_running(self) -> None:
            if self.process is not None and self.process.state() != QProcess.NotRunning:
                self._append_console("[!] Process did not exit after terminate; killing.")
                self._append_app_log("[!] Process did not exit after terminate; killing.")
                self.process.kill()

        def keyPressEvent(self, event: QKeyEvent) -> None:
            if self._handle_stop_shortcut(event, QApplication.focusWidget()):
                return
            super().keyPressEvent(event)

        def eventFilter(self, obj: Any, event: Any) -> bool:
            if event.type() == QEvent.KeyPress and self._handle_stop_shortcut(event, obj):
                return True
            return super().eventFilter(obj, event)

        def _handle_stop_shortcut(self, event: QKeyEvent, focused: Any) -> bool:
            key = event.key()
            modifiers = event.modifiers()
            if key == Qt.Key_Period and modifiers & Qt.MetaModifier:
                self._stop_scan("console shortcut")
                event.accept()
                return True
            if key == Qt.Key_C and modifiers & Qt.ControlModifier:
                if focused is self.console and self.console.textCursor().hasSelection():
                    return False
                self._stop_scan("console shortcut")
                event.accept()
                return True
            return False

        def _refresh_state(self) -> None:
            run_dir = self.current_run_dir
            if run_dir is None:
                self._update_artifact_buttons()
                return
            self.run_result = _read_json(run_dir / "run_result.json")
            self.live_stages = _read_json(run_dir / "stages_live.json")
            self._render_metrics()
            self._render_tool_table(self.live_stages)
            self._render_findings()
            self._render_summary()
            self._update_artifact_buttons()

        def _render_metrics(self) -> None:
            summary = self.run_result.get("summary") if isinstance(self.run_result.get("summary"), dict) else {}
            report_path = self.current_run_dir / "report.html" if self.current_run_dir else None
            self.metric_labels["Run"].setText(str(self.run_result.get("run_state") or ("running" if self._is_running() else "idle")))
            self.metric_labels["Katana"].setText(str(_safe_int(summary.get("katana_count"))))
            self.metric_labels["Gobuster"].setText(str(_safe_int(summary.get("gobuster_total_hits"))))
            self.metric_labels["FFUF"].setText(str(_safe_int(summary.get("ffuf_hits"))))
            self.metric_labels["Nuclei"].setText(str(_safe_int(summary.get("nuclei_findings_count"))))
            self.metric_labels["Report"].setText("ready" if report_path and report_path.exists() else "waiting")

        def _build_tool_rows(self, live_stages: dict[str, Any]) -> list[tuple[str, str, str, str]]:
            run_stages = self.run_result.get("stages") if isinstance(self.run_result.get("stages"), dict) else {}
            stages = live_stages if live_stages else (run_stages if isinstance(run_stages, dict) else {})
            summary = self.run_result.get("summary") if isinstance(self.run_result.get("summary"), dict) else {}
            skipped = _normalize_skipped(self.run_result)
            rows: list[tuple[str, str, str, str]] = []
            for name, label in _TOOL_ORDER:
                stage = stages.get(name) if isinstance(stages.get(name), dict) else {}
                selected = bool(self.selected_tools.get(name, _DEFAULT_TOOL_ENABLED.get(name, True)))
                reason = str(self.auto_skipped_tools.get(name) or "")
                status = str(stage.get("status") or ("skipped" if name in skipped else "pending"))
                if not selected:
                    status = "skipped"
                    metric = "disabled"
                elif reason and status in {"pending", "skipped"}:
                    status = "auto-skipped"
                    metric = "selected"
                else:
                    metric = _tool_metric(name, summary, stage)
                rows.append((label, status, metric, reason))
            return rows

        def _render_tool_table(self, live_stages: dict[str, Any]) -> None:
            rows = self._build_tool_rows(live_stages)
            self.stage_table.setRowCount(len(rows))
            for row_idx, row in enumerate(rows):
                for col_idx, value in enumerate(row):
                    item = QTableWidgetItem(value)
                    self.stage_table.setItem(row_idx, col_idx, item)
            self.stage_table.resizeColumnsToContents()

        def _render_findings(self) -> None:
            self.findings_list.clear()
            if self.current_run_dir is None:
                return
            for finding in _findings_from_jsonl(self.current_run_dir, self.run_result):
                text = f"{finding['severity'].upper()}  {finding['name']}  {finding['matched_at']}"
                item = QListWidgetItem(text)
                item.setToolTip(f"{finding['template_id']}\n{finding['matched_at']}")
                self.findings_list.addItem(item)

        def _render_summary(self) -> None:
            target = self.target_input.text().strip() or "-"
            meta = self.run_result.get("meta") if isinstance(self.run_result.get("meta"), dict) else {}
            traffic = self.run_result.get("traffic") if isinstance(self.run_result.get("traffic"), dict) else {}
            requested = traffic.get("requested_profile") or traffic.get("profile") or meta.get("traffic_profile") or self._selected_profile()
            effective = traffic.get("effective_profile") or traffic.get("profile") or requested
            run_dir = str(self.current_run_dir or "")
            self.summary_label.setText(
                f"Target: {target}\n"
                f"Traffic: requested={requested} effective={effective}\n"
                f"Report depth: {self.report_depth_select.currentText()}\n"
                f"Run dir: {run_dir}"
            )

        def _update_artifact_buttons(self) -> None:
            run_dir = self.current_run_dir
            self.open_run_folder_button.setEnabled(bool(run_dir and run_dir.exists()))
            self.open_report_button.setEnabled(bool(run_dir and (run_dir / "report.html").exists()))
            self.open_raw_log_button.setEnabled(bool(run_dir and (run_dir / "reconbot.log").exists()))
            self.open_state_json_button.setEnabled(bool(run_dir and (run_dir / "run_result.json").exists()))

        def _open_artifact(self, filename: str) -> None:
            if self.current_run_dir is None:
                return
            path = self.current_run_dir / filename
            if path.exists():
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

        def _open_run_folder(self) -> None:
            if self.current_run_dir is not None and self.current_run_dir.exists():
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.current_run_dir)))

        def _is_running(self) -> bool:
            return bool(self.process is not None and self.process.state() != QProcess.NotRunning)

        def closeEvent(self, event: Any) -> None:
            if self._is_running():
                self._stop_scan("button")
            event.accept()

    app = QApplication.instance()
    owns_app = app is None
    if app is None:
        app = QApplication(sys.argv[:1])
    previous_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, lambda *_args: app.quit())
    window = ReconBotOperatorConsole()
    window.show()
    try:
        return app.exec() if owns_app else 0
    finally:
        signal.signal(signal.SIGINT, previous_sigint)
