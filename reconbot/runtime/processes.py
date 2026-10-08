"""Run-owned subprocesses, including cancellation of their process groups."""
from __future__ import annotations

import contextvars
import os
import signal
import subprocess as _subprocess
import threading
import time
from contextlib import contextmanager

PIPE = _subprocess.PIPE
STDOUT = _subprocess.STDOUT
DEVNULL = _subprocess.DEVNULL
TimeoutExpired = _subprocess.TimeoutExpired
CalledProcessError = _subprocess.CalledProcessError
CompletedProcess = _subprocess.CompletedProcess
_owned = contextvars.ContextVar("reconbot_processes", default=None)


def _signal_group(proc, sig):
    deadline = time.monotonic() + 0.25
    while True:
        try:
            if os.name == "posix":
                os.killpg(proc.pid, sig)
            elif proc.poll() is None:
                proc.terminate() if sig == signal.SIGTERM else proc.kill()
            return
        except ProcessLookupError:
            return
        except PermissionError:
            # macOS may report EPERM while an orphaned, terminated group is
            # awaiting reaping. Retry briefly; real permission failures still
            # propagate rather than pretending cleanup succeeded.
            if proc.poll() is None or time.monotonic() >= deadline:
                raise
            time.sleep(0.01)


def terminate_processes(processes, grace=2.0):
    processes = [proc for proc in processes if not getattr(proc, "_group_cleaned", False)]
    for proc in processes:
        _signal_group(proc, signal.SIGTERM)
    deadline = time.monotonic() + grace
    for proc in processes:
        try:
            proc.wait(timeout=max(0, deadline - time.monotonic()))
        except TimeoutExpired:
            pass
    # Also terminate descendants if the group leader has already exited.
    for proc in processes:
        _signal_group(proc, signal.SIGKILL)
        proc.wait()
        proc._group_cleaned = True
        owner = getattr(proc, "_owner", None)
        if owner is not None and proc in owner:
            owner.remove(proc)


class Popen(_subprocess.Popen):
    def __init__(self, *args, **kwargs):
        if os.name == "posix":
            kwargs["start_new_session"] = True
        super().__init__(*args, **kwargs)
        self._group_cleaned = False
        self._owner = _owned.get()
        if self._owner is not None:
            self._owner.append(self)


def run(*popenargs, input=None, capture_output=False, timeout=None, check=False, **kwargs):
    if input is not None:
        if kwargs.get("stdin") is not None:
            raise ValueError("stdin and input cannot both be supplied")
        kwargs["stdin"] = PIPE
    if capture_output:
        if kwargs.get("stdout") is not None or kwargs.get("stderr") is not None:
            raise ValueError("capture_output conflicts with stdout/stderr")
        kwargs["stdout"] = kwargs["stderr"] = PIPE
    with Popen(*popenargs, **kwargs) as proc:
        try:
            stdout, stderr = proc.communicate(input, timeout=timeout)
        except TimeoutExpired as exc:
            terminate_processes([proc])
            stdout, stderr = proc.communicate()
            exc.output, exc.stderr = stdout, stderr
            raise
        except BaseException:
            terminate_processes([proc])
            raise
        # Release finished processes now, rather than retaining their PIDs for
        # a long scan. Any descendants still in the group are cleaned here.
        terminate_processes([proc])
        result = CompletedProcess(proc.args, proc.returncode, stdout, stderr)
        if check:
            result.check_returncode()
        return result


@contextmanager
def process_scope():
    """Ensure no scanner survives success, failure, Ctrl+C, or app shutdown."""
    if _owned.get() is not None:
        yield
        return
    children = []
    token = _owned.set(children)
    old_handlers = {}

    def interrupted(signum, _frame):
        for sig in old_handlers:
            signal.signal(sig, signal.SIG_IGN)
        raise KeyboardInterrupt(f"signal {signum}")

    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGINT, signal.SIGTERM, getattr(signal, "SIGHUP", signal.SIGTERM)):
            if sig not in old_handlers:
                old_handlers[sig] = signal.signal(sig, interrupted)
    try:
        yield
    finally:
        # A second shutdown signal must not interrupt group cleanup.
        for sig in (*old_handlers, signal.SIGINT):
            if threading.current_thread() is threading.main_thread():
                old_handlers.setdefault(sig, signal.getsignal(sig))
                signal.signal(sig, signal.SIG_IGN)
        try:
            terminate_processes(children)
        finally:
            _owned.reset(token)
            for sig, handler in old_handlers.items():
                signal.signal(sig, handler)
