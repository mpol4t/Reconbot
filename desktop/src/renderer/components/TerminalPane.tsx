import { t } from "../lib/i18n";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { useEffect, useRef } from "react";
import type { RunStateSnapshot } from "../../shared/api";

interface TerminalPaneProps {
  active: boolean;
  runState: RunStateSnapshot;
  onStop: () => void;
}

export default function TerminalPane({ active, runState, onStop }: TerminalPaneProps): JSX.Element {
  const hostRef = useRef<HTMLDivElement | null>(null);
  const terminalRef = useRef<Terminal | null>(null);
  const fitRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    if (!hostRef.current || terminalRef.current) return undefined;
    let disposed = false;
    const api = window.reconbot;
    const terminal = new Terminal({
      cursorBlink: true,
      convertEol: true,
      fontFamily: "Menlo, Monaco, Consolas, 'SFMono-Regular', monospace",
      fontSize: 13,
      lineHeight: 1.25,
      scrollback: 5000,
      theme: {
        background: "#12161b",
        foreground: "#c9d1db",
        cursor: "#8bd5cb",
        selectionBackground: "#174b55",
        black: "#061118",
        blue: "#28b7ff",
        brightBlue: "#66e8ff",
        green: "#32f28a",
        brightGreen: "#6dffad",
        red: "#ff4d73",
        brightRed: "#ff7596",
        yellow: "#ffc857",
        brightYellow: "#ffe08a"
      }
    });
    const host = hostRef.current;
    const fitAddon = new FitAddon();
    terminal.loadAddon(fitAddon);
    terminal.open(host);
    let fitFrame = 0;
    let lastGeometry = "";
    const scheduleFit = (): void => {
      cancelAnimationFrame(fitFrame);
      fitFrame = requestAnimationFrame(() => {
        if (disposed || host.clientWidth <= 0 || host.clientHeight <= 0) return;
        fitAddon.fit();
        const geometry = `${terminal.cols}x${terminal.rows}`;
        if (geometry !== lastGeometry) {
          lastGeometry = geometry;
          api?.resizeTerminal?.(terminal.cols, terminal.rows);
        }
      });
    };
    fitRef.current = scheduleFit;
    const resizeObserver = new ResizeObserver(scheduleFit);
    resizeObserver.observe(host);
    window.addEventListener("resize", scheduleFit);
    void document.fonts.ready.then(() => { if (!disposed) scheduleFit(); });
    scheduleFit();
    const inputDisposable = terminal.onData((data) => api?.writeTerminal?.(data));
    const removeTerminalListener = api?.onTerminalData?.((data) => terminal.write(data)) || (() => undefined);
    terminalRef.current = terminal;
    const writeInitialTerminalState = (buffer = ""): void => {
      if (disposed) return;
      if (buffer) {
        terminal.write(buffer);
      } else if (api) {
        terminal.write("\x1b[36mReconBot PTY ready.\x1b[0m\r\n");
      } else {
        terminal.write("\x1b[33mDesktop IPC hazır değil; terminal güvenli modda.\x1b[0m\r\n");
      }
      if (active) terminal.focus();
    };
    if (api?.getTerminalBuffer) {
      api.getTerminalBuffer()
        .then((buffer) => writeInitialTerminalState(buffer || ""))
        .catch(() => writeInitialTerminalState(""));
    } else {
      writeInitialTerminalState("");
    }

    return () => {
      disposed = true;
      cancelAnimationFrame(fitFrame);
      resizeObserver.disconnect();
      window.removeEventListener("resize", scheduleFit);
      fitRef.current = null;
      inputDisposable.dispose();
      removeTerminalListener();
      terminal.dispose();
      terminalRef.current = null;
    };
  }, []);

  useEffect(() => {
    if (active) {
      fitRef.current?.();
      terminalRef.current?.focus();
    }
  }, [active]);

  const clearTerminal = (): void => {
    terminalRef.current?.clear();
  };

  const copyBuffer = async (): Promise<void> => {
    if (!window.reconbot?.getTerminalBuffer || !window.reconbot?.copyText) return;
    const buffer = await window.reconbot.getTerminalBuffer();
    await window.reconbot.copyText(buffer);
  };

  return (
    <section className="terminal-wrap">
      <header className="terminal-header cockpit-panel">
        <div>
          <span className="micro-label">{t("Terminal")}</span>
          <h2>{t("Interactive PTY")}</h2>
        </div>
        <div className="terminal-tools">
          <span className={`terminal-status ${runState.runState === "running" ? "live" : ""}`}>
            {runState.runState === "running" ? t("connected / running") : t("connected / idle")}
          </span>
          <button type="button" onClick={clearTerminal}>{t("Clear")}</button>
          <button type="button" onClick={copyBuffer}>{t("Copy")}</button>
          <button type="button" className="danger-button" onClick={onStop}>{t("Stop")}</button>
          <small>{t("Ctrl+C forwards to PTY")}</small>
        </div>
      </header>
      <div className="terminal-frame">
        <div ref={hostRef} className="terminal-host" />
      </div>
    </section>
  );
}
