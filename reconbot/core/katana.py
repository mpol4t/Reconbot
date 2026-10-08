"""TR: Katana, canlı URL'leri crawl edip yeni endpoint/path keşfeder (httpx output'u besler).
EN: Katana crawls live URLs to discover new endpoints/paths (fed by httpx output)."""

from __future__ import annotations

from reconbot.runtime import processes as subprocess
from typing import Iterable, Iterator


class KatanaRunError(RuntimeError):
    """Raised when every Katana subprocess attempt fails before producing output."""


def _normalize_urls(urls: Iterable[str]) -> list[str]:
    cleaned: list[str] = []
    for u in urls:
        s = (u or "").strip()
        if not s:
            continue
        cleaned.append(s)

    # stable de-dup
    return sorted(set(cleaned))


def _chunks(items: list[str], size: int) -> Iterator[list[str]]:
    if size <= 0:
        size = 50
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _run_katana_once(
    urls: list[str],
    depth: int,
    js_crawl: bool,
    timeout_sec: int,
    force_single: bool,
    concurrency: int,
    parallelism: int,
    rate_limit: int,
    delay_sec: int,
) -> tuple[int, str, str]:
    """Run katana once and return (returncode, stdout, stderr)."""

    cmd: list[str] = ["katana", "-silent", "-nc", "-duc", "-d", str(max(1, depth))]

    if concurrency > 0:
        cmd.extend(["-c", str(concurrency)])
    if parallelism > 0:
        cmd.extend(["-p", str(parallelism)])
    if rate_limit > 0:
        cmd.extend(["-rl", str(rate_limit)])
    if delay_sec > 0:
        cmd.extend(["-rd", str(delay_sec)])

    if js_crawl:
        cmd.append("-jc")

    # Katana supports either single target (-u) or list (-list)
    if force_single or len(urls) == 1:
        cmd.extend(["-u", urls[0]])
    else:
        cmd.append("-list")
        cmd.extend(urls)

    try:
        if timeout_sec and int(timeout_sec) > 0:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
        else:
            p = subprocess.run(cmd, capture_output=True, text=True)
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired as exc:
        # communicate() can retain bytes even when the subprocess uses text=True.
        def captured_text(value: str | bytes | None) -> str:
            return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value or ""

        output = captured_text(exc.output)
        error = captured_text(exc.stderr).strip()
        return 124, output, "\n".join(filter(None, [error, f"Katana timeout ({timeout_sec}s)"]))


def run_katana(
    urls: list[str],
    depth: int = 3,
    js_crawl: bool = False,
    auto_js_crawl: bool = True,
    auto_js_threshold: int = 5,
    timeout_sec: int = 120,
    batch_size: int = 50,
    prefer_single_u_under: int = 25,
    concurrency: int = 0,
    parallelism: int = 0,
    rate_limit: int = 0,
    delay_sec: int = 0,
    max_urls: int = 0,
    diagnostics: dict | None = None,
) -> list[str]:
    """Crawl given URLs with Katana and return discovered endpoints.

    Parameters
    ----------
    urls:
        Base/live URLs to crawl (typically httpx output).
    depth:
        Crawl depth (default 3).
    js_crawl:
        Force-enable JS crawling (-jc).
    auto_js_crawl:
        If True and `js_crawl` is False, automatically try a second pass with -jc
        when the first pass returns very few results.
    auto_js_threshold:
        If first pass yields <= this count, trigger the auto JS pass.
    timeout_sec:
        Timeout in seconds for each katana subprocess call.
    batch_size:
        Number of URLs to batch per katana call when using -list.
    prefer_single_u_under:
        For URL counts under this, prefer running per-URL (-u) to avoid -list quirks.
    concurrency:
        Concurrency level (-c) for katana.
    parallelism:
        Parallelism level (-p) for katana.
    rate_limit:
        Rate limit (-rl) for katana.
    delay_sec:
        Request delay (-rd) in seconds for katana.

    Returns
    -------
    list[str]
        De-duplicated list of discovered URLs.
    """

    base_urls = _normalize_urls(urls)
    if not base_urls:
        return []

    results_set: set[str] = set()
    hard_failures: list[str] = []
    successful_attempts = 0

    # Decide execution strategy
    # - For small URL lists, run per-URL to avoid `-list` quirks and make outputs predictable.
    # - For larger lists, run in batches (arg length safety) using -list.
    force_single = len(base_urls) <= max(1, prefer_single_u_under)

    for batch in _chunks(base_urls, batch_size if not force_single else 1):
        if max_urls and len(results_set) >= max_urls:
            break
        rc, out, err = _run_katana_once(
            batch,
            depth=depth,
            js_crawl=js_crawl,
            timeout_sec=timeout_sec,
            force_single=force_single,
            concurrency=concurrency,
            parallelism=parallelism,
            rate_limit=rate_limit,
            delay_sec=delay_sec,
        )

        if rc != 0:
            # Hard failure for this batch
            msg = err.strip() or "(stderr boş)"
            print(f"[!] Katana hata (rc={rc}) batch={len(batch)}: {msg}")
            hard_failures.append(f"rc={rc} batch={len(batch)}: {msg}")
            if not out.strip():
                continue
        else:
            successful_attempts += 1

        for ln in out.splitlines():
            s = ln.strip()
            if s:
                results_set.add(s)

    results = sorted(results_set)

    # Optional second pass with JS crawling if results are too few
    if (not js_crawl) and auto_js_crawl and (len(results) <= max(0, auto_js_threshold)):
        js_set: set[str] = set(results_set)

        for batch in _chunks(base_urls, batch_size if not force_single else 1):
            if max_urls and len(js_set) >= max_urls:
                break
            rc2, out2, err2 = _run_katana_once(
                batch,
                depth=depth,
                js_crawl=True,
                timeout_sec=timeout_sec,
                force_single=force_single,
                concurrency=concurrency,
                parallelism=parallelism,
                rate_limit=rate_limit,
                delay_sec=delay_sec,
            )

            if rc2 != 0:
                msg2 = err2.strip() or "(stderr boş)"
                print(f"[i] Katana JS-crawl hata (rc={rc2}) batch={len(batch)}: {msg2}")
                hard_failures.append(f"js rc={rc2} batch={len(batch)}: {msg2}")
                if not out2.strip():
                    continue
            else:
                successful_attempts += 1

            for ln in out2.splitlines():
                s = ln.strip()
                if s:
                    js_set.add(s)

        results = sorted(js_set)

    if diagnostics is not None:
        diagnostics.update(errors=hard_failures, successful_attempts=successful_attempts)
    if not results and hard_failures and successful_attempts <= 0:
        raise KatanaRunError("; ".join(hard_failures[:4]))

    return results[:max_urls] if max_urls else results
