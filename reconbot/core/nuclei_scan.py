import json
from reconbot.runtime import processes as subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional, Tuple


def start_nuclei(
    targets: list[str],
    *,
    run_dir: Optional[Path] = None,
    nuclei_args: Optional[list[str]] = None,
) -> tuple[Optional[subprocess.Popen], Optional[Path], Optional[Path], Optional[Path]]:
    """Start nuclei in a SAFE way (no daemon threads, no stderr PIPE).

    Returns:
        (proc, output_path, log_path, targets_path)

    Notes:
    - We NEVER use stderr=PIPE here. That pattern can deadlock (buffer fills) and it
      also contributes to ugly shutdown crashes if background threads are printing.
    - We redirect both stdout and stderr to a log file.
    """

    if not targets:
        return None, None, None, None

    # Decide where artifacts live
    base_dir = Path(run_dir) if run_dir else Path(tempfile.mkdtemp(prefix="reconbot_nuclei_"))
    base_dir.mkdir(parents=True, exist_ok=True)

    targets_path = base_dir / "nuclei_targets.txt"
    with targets_path.open("w", encoding="utf-8") as f:
        f.write("\n".join([t.strip() for t in targets if (t or "").strip()]) + "\n")

    output_path = base_dir / "nuclei_output.jsonl"
    log_path = base_dir / "nuclei.log"

    cmd = [
        "nuclei",
        "-l",
        str(targets_path),
        "-jsonl",
        "-o",
        str(output_path),
    ]
    if nuclei_args:
        cmd.extend(nuclei_args)

    # Redirect stdout+stderr to a file (stable, no PIPE)
    with log_path.open("a", encoding="utf-8") as logf:
        proc = subprocess.Popen(
            cmd,
            stdout=logf,
            stderr=logf,
            text=True,
        )

    print(f"[+] Nuclei started with PID: {proc.pid}")

    return proc, output_path, log_path, targets_path


def wait_nuclei(
    proc: subprocess.Popen,
    *,
    heartbeat_seconds: int = 5,
    label: str = "Nuclei",
) -> int:
    """Block until nuclei finishes.

    Prints a low-noise heartbeat so the user understands the program is still running.
    Returns process return code.

    IMPORTANT: This function keeps the main thread alive (A plan).
    """

    start = time.time()
    last_beat = 0.0

    try:
        while True:
            rc = proc.poll()
            if rc is not None:
                elapsed = int(time.time() - start)
                print(f"[*] {label} finished. rc={rc} elapsed={elapsed}s")
                return rc

            now = time.time()
            if now - last_beat >= float(max(1, heartbeat_seconds)):
                elapsed = int(now - start)
                print(f"[*] {label} running... elapsed={elapsed}s")
                last_beat = now

            time.sleep(1)

    except KeyboardInterrupt:
        # Graceful shutdown path
        print(f"[!] {label} interrupted by user. Terminating...")
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        raise


def _tail_text(path: Path, max_chars: int = 4000) -> str:
    """Read the last max_chars characters of a text file (best effort)."""
    try:
        if not path.exists():
            return ""
        data = path.read_text(encoding="utf-8", errors="replace")
        if len(data) <= max_chars:
            return data
        return data[-max_chars:]
    except Exception:
        return ""


def parse_nuclei_output(
    output_path: Path,
    returncode: int,
    *,
    log_path: Optional[Path] = None,
) -> dict:
    """Parse nuclei jsonl output into a stable dict.

    Status values:
        - Success: returncode==0 and parsed cleanly
        - Clean: output empty (no findings)
        - Partial: had parse errors or non-zero rc but still had findings
        - Error: non-zero rc and no findings (or output missing)
    """

    findings: list[dict] = []
    parse_error_count = 0
    seen = set()

    stderr_tail = _tail_text(log_path) if log_path else ""

    if not output_path.exists():
        return {
            "Status": "Error",
            "Error": stderr_tail or "nuclei output file missing",
            "Findings": [],
        }

    with output_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = (line or "").strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                if not isinstance(data, dict) or not isinstance(data.get("info"), dict):
                    parse_error_count += 1
                    continue
                template = data.get("templateID") or data.get("template-id")
                host = data.get("host")
                matched_at = data.get("matched-at") or data.get("matchedAt") or host
                if not template or not matched_at:
                    parse_error_count += 1
                    continue
                key = f"{matched_at}:{template}"

                if key in seen:
                    continue
                seen.add(key)

                findings.append(data)

            except json.JSONDecodeError:
                parse_error_count += 1
                continue

    if (returncode != 0 or parse_error_count > 0) and not findings:
        return {
            "Status": "Error",
            "Error": stderr_tail or f"nuclei failed rc={returncode}; invalid rows={parse_error_count}",
            "Findings": [],
        }

    if returncode != 0 or parse_error_count > 0:
        return {
            "Status": "Partial",
            "Error": stderr_tail or f"nuclei rc={returncode}; invalid rows={parse_error_count}",
            "Findings": findings,
        }

    return {
        "Status": "Success" if findings else "Clean",
        "Error": None,
        "Findings": findings,
    }
