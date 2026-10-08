from __future__ import annotations

import argparse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Reconbot - Automated recon tool (IP/domain, Nmap + HTTP discovery + Gobuster + Nuclei)"
    )
    parser.add_argument(
        "target",
        nargs="?",
        default="",
        help="Target (IP/domain) or command: app | generate-report | validate-decision-fixtures | validate-correlation-fixtures"
    )
    parser.add_argument(
        "--check-runtime",
        dest="check_runtime",
        action="store_true",
        help="Check Python runtime dependency imports and exit.",
    )
    parser.add_argument(
        "-w", "--wordlist",
        required=False,
        help="Path to gobuster wordlist"
    )
    parser.add_argument(
        "-o", "--output-dir",
        default=None,
        help="Base output directory. Artifacts go to <base>/runs/<timestamp>/ and a mirror is kept at <base>/latest/. Default: reconbot/output"
    )
    parser.add_argument(
        "-c", "--config",
        default=None,
        help="YAML config dosyası. CLI argümanları config'i override eder.",
    )
    parser.add_argument(
        "--run-dir",
        default=None,
        help="Developer-only: existing run directory used with 'generate-report' target to regenerate report.html without running scanners.",
    )
    parser.add_argument(
        "--report-depth",
        dest="report_depth",
        choices=("summary", "balanced", "deep"),
        default=None,
        help="Report rendering depth: summary, balanced, or deep. Default: balanced.",
    )
    parser.add_argument(
        "--traffic-profile",
        dest="traffic_profile",
        choices=("safe", "balanced", "fast"),
        default=None,
        help="Traffic profile: safe, balanced, or fast. Default: balanced.",
    )
    parser.add_argument("--nmap-timing", dest="nmap_timing", default=None, help="Nmap timing template (T0-T4). T5 is not allowed.")
    parser.add_argument("--subfinder-rate-limit", dest="subfinder_rate_limit", type=int, default=None, help="Subfinder rate-limit (requests per second).")
    parser.add_argument("--dnsx-rate-limit", dest="dnsx_rate_limit", type=int, default=None, help="DNSX rate-limit (requests per second).")
    parser.add_argument("--httpx-rate-limit", dest="httpx_rate_limit", type=int, default=None, help="HTTPX rate-limit (requests per second).")
    parser.add_argument("--dnsx-batch", dest="dnsx_batch", type=int, default=None, help="DNSX batch size (input chunk size).")
    parser.add_argument("--httpx-batch", dest="httpx_batch", type=int, default=None, help="HTTPX batch size (input chunk size).")
    parser.add_argument("--gobuster-threads", dest="gobuster_threads", type=int, default=None, help="Gobuster threads (-t).")
    parser.add_argument("--gobuster-timeout", dest="gobuster_timeout", type=int, default=None, help="Gobuster timeout seconds.")
    parser.add_argument("--gobuster-allowed-status", dest="gobuster_allowed_status", default=None, help="Comma-separated allowed status codes for gobuster (e.g., 200,301,302,401,403).")
    parser.add_argument("--ffuf-threads", dest="ffuf_threads", type=int, default=None, help="FFUF threads (-t).")
    parser.add_argument("--ffuf-enabled", dest="ffuf_enabled", action=argparse.BooleanOptionalAction, default=None, help="Enable/disable FFUF stage.")
    parser.add_argument("--ffuf-rate", dest="ffuf_rate", type=int, default=None, help="FFUF request rate (-rate). 0 means ffuf default.")
    parser.add_argument("--ffuf-timeout", dest="ffuf_timeout", type=int, default=None, help="FFUF timeout seconds (-timeout).")
    parser.add_argument("--ffuf-allowed-status", dest="ffuf_allowed_status", default=None, help="Comma-separated allowed status codes for ffuf (e.g., 200,204,301,302,401,403).")
    parser.add_argument("--historical-urls-enabled", dest="historical_urls_enabled", action=argparse.BooleanOptionalAction, default=None, help="Enable/disable optional gau/waybackurls historical URL discovery.")
    parser.add_argument("--historical-max-domains", dest="historical_urls_max_domains", type=int, default=None, help="Max selected domains to send to historical URL tools.")
    parser.add_argument("--historical-max-urls", dest="historical_urls_max_urls", type=int, default=None, help="Max normalized historical URLs to keep before live probing.")
    parser.add_argument("--historical-live-check-limit", dest="historical_urls_live_check_limit", type=int, default=None, help="Max historical URLs to probe with httpx for liveness.")
    parser.add_argument("--historical-timeout", dest="historical_urls_timeout_sec", type=int, default=None, help="Timeout seconds per historical URL tool/domain call.")
    parser.add_argument("--screenshots-enable", dest="screenshots_enable", action=argparse.BooleanOptionalAction, default=None, help="Enable/disable optional gowitness screenshot capture.")
    parser.add_argument("--screenshots-limit", dest="screenshots_limit", type=int, default=None, help="Max already-live URLs to screenshot.")
    parser.add_argument("--screenshots-timeout", dest="screenshots_timeout", type=int, default=None, help="Total timeout seconds for the gowitness screenshot stage.")
    parser.add_argument("--katana-depth", dest="katana_depth", type=int, default=None, help="Katana crawl depth (-d).")
    parser.add_argument("--katana-js", dest="katana_js_crawl", action=argparse.BooleanOptionalAction, default=None, help="Enable/disable Katana JS crawl (-jc).")
    parser.add_argument("--checks-max-urls", dest="checks_max_urls", type=int, default=None, help="Max URLs to check in web_checks.")
    parser.add_argument("--checks-timeout", dest="checks_timeout_sec", type=int, default=None, help="Timeout seconds per URL in web_checks.")
    parser.add_argument("--checks-max-body-bytes", type=int, default=None, help="Maximum decoded response bytes per web check.")
    parser.add_argument("--checks-follow-redirects", action=argparse.BooleanOptionalAction, default=None, help="Follow HTTP redirects in web checks.")
    parser.add_argument("--checks-pool-limit", dest="checks_pool_limit", type=int, default=None, help="Max URLs kept in checks pool before requesting.")
    parser.add_argument("--nuclei-severity", dest="nuclei_severity", default=None, help="Nuclei severities filter (e.g., critical,high,medium).")
    parser.add_argument("--nuclei-rate-limit", dest="nuclei_rate_limit", type=int, default=None, help="Nuclei rate-limit (requests per second).")
    parser.add_argument("--nuclei-disabled", dest="nuclei_enabled", action="store_false", default=None, help="Disable Nuclei stage.")
    parser.add_argument("--nuclei-drop-query", dest="nuclei_drop_query", action=argparse.BooleanOptionalAction, default=None, help="Drop query string when building nuclei targets.")
    parser.add_argument("--nuclei-pool-limit", dest="nuclei_pool_limit", type=int, default=None, help="Cap nuclei target list to avoid overload.")
    parser.add_argument("--verbose", dest="verbose", action=argparse.BooleanOptionalAction, default=None, help="Enable/disable verbose logs (engine).")
    parser.add_argument("--gui", dest="gui", action=argparse.BooleanOptionalAction, default=False, help="Run sonunda ilk GUI bootstrap dashboard'unu aç.")
    parser.add_argument("--web", dest="web", action="store_true", help="'app' komutunda legacy browser dashboard'u aç.")
    return parser
