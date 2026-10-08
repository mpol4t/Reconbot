from __future__ import annotations

from datetime import datetime
from pathlib import Path
import os
import fcntl
from uuid import uuid4

def _prepare_output_dirs(output_dir_arg: str | None) -> tuple[Path, Path, str]:
    """Return (run_dir, latest_dir, base_dir_str) using a stable folder standard.

    Folder standard (single source of truth):
      - base_dir:
          * if user passes --output-dir, use it as base_dir
            - if they pass something ending with `/latest`, we treat its parent as base_dir
          * else default to: reconbot/output

      - per-run output:
          base_dir/runs/<timestamp>-<unique-id>/

      - atomic latest pointer:
          base_dir/latest/

    All artifacts stay in run_dir; latest points to that complete directory.

    Returns:
      (run_dir, latest_dir, base_dir_str)
    """
    default_base = (Path(__file__).resolve().parent.parent / "output").resolve()

    if output_dir_arg:
        user_path = Path(output_dir_arg).expanduser().absolute()
        # If user points to .../latest, treat parent as the base.
        base_dir = (user_path.parent if user_path.name.lower() == "latest" else user_path).resolve()
    else:
        base_dir = default_base

    ts = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid4().hex[:8]
    run_dir = (base_dir / "runs" / ts).resolve()
    latest_dir = base_dir / "latest"

    run_dir.mkdir(parents=True, exist_ok=False)
    latest_dir.mkdir(parents=True, exist_ok=True)

    return run_dir, latest_dir, str(base_dir)


def sync_latest(run_dir: Path | str, latest_dir: Path | str) -> None:
    """Atomically switch the latest run pointer; preserve legacy directories."""
    run_path = Path(run_dir).resolve()
    # Do not resolve latest: it may already point to an older run.
    latest_path = Path(latest_dir).absolute()
    latest_path.parent.mkdir(parents=True, exist_ok=True)
    with (latest_path.parent / ".latest.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        temporary = latest_path.parent / f".latest-{uuid4().hex}"
        try:
            temporary.symlink_to(run_path, target_is_directory=True)
            if latest_path.exists() and not latest_path.is_symlink():
                backup = latest_path.parent / f".latest-legacy-{uuid4().hex}"
                latest_path.rename(backup)
            os.replace(temporary, latest_path)
        finally:
            temporary.unlink(missing_ok=True)
