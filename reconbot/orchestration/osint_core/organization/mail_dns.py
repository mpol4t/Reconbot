"""Passive MX/SPF/DMARC DNS checks for OSINT organization context."""

from __future__ import annotations

import ipaddress
import platform
import re
import sys
from datetime import datetime, timezone
from typing import Any, Callable


DnsQueryFunc = Callable[[str, str, int], dict[str, Any]]


def _normalize_hostname(value: str) -> str:
    return str(value or "").strip().lower().strip(".")


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value or "").strip())
        return True
    except ValueError:
        return False


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def dns_runtime_diagnostic() -> dict[str, Any]:
    diagnostic: dict[str, Any] = {
        "python_executable": sys.executable,
        "python_version": platform.python_version(),
        "sys_path_excerpt": [str(item) for item in sys.path[:8]],
        "dns_resolver_import_ok": False,
    }
    try:
        import dns.resolver  # type: ignore[import-not-found]  # noqa: F401
    except Exception as exc:
        diagnostic["dns_resolver_import_error"] = f"{type(exc).__name__}: {exc}"
        return diagnostic
    diagnostic["dns_resolver_import_ok"] = True
    return diagnostic


def query_dns_records(name: str, record_type: str, timeout: int) -> dict[str, Any]:
    normalized = _normalize_hostname(name)
    rrtype = str(record_type or "").strip().upper()
    base_result = {"resolver_method": "dnspython"}
    if "/" in normalized or "@" in normalized or not re.fullmatch(r"[a-z0-9._-]+", normalized):
        normalized = ""
    if not normalized or not rrtype:
        return {**base_result, "status": "resolver_error", "records": [], "validation_error": "invalid_dns_query"}
    try:
        import dns.resolver  # type: ignore[import-not-found]
    except Exception as exc:
        import_error = f"{type(exc).__name__}: {exc}"
        return {
            **base_result,
            "status": "dependency_missing",
            "records": [],
            "validation_error": f"dependency_missing: {import_error}",
            "dns_resolver_import_error": import_error,
        }

    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = max(1, min(int(timeout or 3), 5))
        resolver.timeout = max(1, min(int(timeout or 3), 5))
        answers = resolver.resolve(normalized, rrtype)
        records: list[str] = []
        for answer in answers:
            if rrtype == "MX":
                preference = str(getattr(answer, "preference", "")).strip()
                exchange = _normalize_hostname(str(getattr(answer, "exchange", answer)).rstrip("."))
                records.append(f"{preference} {exchange}".strip())
            elif rrtype == "TXT":
                strings = getattr(answer, "strings", None)
                if strings:
                    records.append("".join(part.decode("utf-8", errors="replace") for part in strings))
                else:
                    records.append(str(answer).strip('"'))
            else:
                records.append(str(answer).rstrip("."))
        return {**base_result, "status": "present" if records else "absent", "records": records, "validation_error": ""}
    except Exception as exc:
        exc_name = type(exc).__name__
        if exc_name == "NXDOMAIN":
            return {**base_result, "status": "absent", "records": [], "validation_error": "nxdomain"}
        if exc_name == "NoAnswer":
            return {**base_result, "status": "absent", "records": [], "validation_error": "no_answer"}
        if exc_name in {"Timeout", "LifetimeTimeout"}:
            return {**base_result, "status": "timeout", "records": [], "validation_error": "timeout"}
        return {**base_result, "status": "resolver_error", "records": [], "validation_error": f"resolver_error: {exc_name}: {exc}"}


def mail_infrastructure_intelligence(
    registered_domain: str | None,
    timeout: int,
    *,
    query_func: DnsQueryFunc = query_dns_records,
    now_func: Callable[[], str] = _now_iso,
) -> dict[str, Any]:
    domain = _normalize_hostname(registered_domain or "")
    checked_at = now_func()
    result: dict[str, Any] = {
        "target_registered_domain": domain,
        "mx_status": "not_checked",
        "mx_records": [],
        "spf_status": "not_checked",
        "dmarc_status": "not_checked",
        "dkim_status": "not_checked",
        "spf_records": [],
        "dmarc_records": [],
        "resolver_method": "dnspython",
        "validation_error": "",
        "mx_validation_error": "",
        "spf_validation_error": "",
        "dmarc_validation_error": "",
        "checked_at": checked_at,
        "observed_public_contacts": [],
        "generated_role_contact_guesses": [],
        "suppressed_contacts": [],
        "email_summary": {
            "observed_public_contacts_count": 0,
            "generated_role_guesses_count": 0,
            "mx_records_count": 0,
            "suppressed_contacts_count": 0,
        },
        "policy": {
            "passive_dns_only": True,
            "no_smtp_connection": True,
            "no_mailbox_validation": True,
            "risk_score_impact": "none",
        },
        "note": "Mail infrastructure does not prove individual inbox existence.",
    }
    if not domain or _looks_like_ip(domain):
        return result

    mx = query_func(domain, "MX", timeout)
    txt = query_func(domain, "TXT", timeout)
    dmarc = query_func(f"_dmarc.{domain}", "TXT", timeout)
    txt_status = str(txt.get("status") or "resolver_error")
    dmarc_query_status = str(dmarc.get("status") or "resolver_error")
    spf_records = [record for record in txt.get("records", []) if str(record).strip().lower().startswith("v=spf1")]
    dmarc_records = [record for record in dmarc.get("records", []) if str(record).strip().lower().startswith("v=dmarc1")]
    spf_status = "present" if spf_records else txt_status if txt_status in {"timeout", "resolver_error", "dependency_missing"} else "absent"
    dmarc_status = "present" if dmarc_records else dmarc_query_status if dmarc_query_status in {"timeout", "resolver_error", "dependency_missing"} else "absent"
    validation_errors = [
        str(item.get("validation_error") or "")
        for item in (mx, txt, dmarc)
        if str(item.get("validation_error") or "").strip()
    ]
    resolver_methods = [
        str(item.get("resolver_method") or "")
        for item in (mx, txt, dmarc)
        if str(item.get("resolver_method") or "").strip()
    ]
    result.update(
        {
            "mx_status": str(mx.get("status") or "resolver_error"),
            "mx_records": list(mx.get("records") or []),
            "mx_validation_error": str(mx.get("validation_error") or mx.get("error") or ""),
            "spf_status": spf_status,
            "spf_records": spf_records,
            "spf_validation_error": str(txt.get("validation_error") or txt.get("error") or ""),
            "dmarc_status": dmarc_status,
            "dmarc_records": dmarc_records,
            "dmarc_validation_error": str(dmarc.get("validation_error") or dmarc.get("error") or ""),
            "resolver_method": ", ".join(sorted(set(resolver_methods))) or "dnspython",
            "validation_error": "; ".join(validation_errors),
            "checked_at": checked_at,
        }
    )
    result["email_summary"]["mx_records_count"] = len(result["mx_records"])
    return result


def _debug_summary(domain: str, timeout: int = 5) -> dict[str, Any]:
    runtime = dns_runtime_diagnostic()
    email = mail_infrastructure_intelligence(domain, timeout)
    return {
        "dns_resolver_import_ok": runtime["dns_resolver_import_ok"],
        "dns_resolver_import_error": runtime.get("dns_resolver_import_error", ""),
        "python_executable": runtime["python_executable"],
        "python_version": runtime["python_version"],
        "mx_status": email["mx_status"],
        "spf_status": email["spf_status"],
        "dmarc_status": email["dmarc_status"],
        "resolver_method": email["resolver_method"],
        "mx_records": email["mx_records"],
        "spf_records": email["spf_records"],
        "dmarc_records": email["dmarc_records"],
        "validation_error": email["validation_error"],
    }


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    domain = _normalize_hostname(args[0] if args else "")
    if not domain:
        print("usage: python3 -m reconbot.orchestration.osint_core.organization.mail_dns <domain>")
        return 2
    summary = _debug_summary(domain)
    print(f"import {'ok' if summary['dns_resolver_import_ok'] else 'fail'}")
    if summary.get("dns_resolver_import_error"):
        print(f"import error: {summary['dns_resolver_import_error']}")
    print(f"python_executable: {summary['python_executable']}")
    print(f"python_version: {summary['python_version']}")
    print(f"MX status: {summary['mx_status']}")
    print(f"SPF status: {summary['spf_status']}")
    print(f"DMARC status: {summary['dmarc_status']}")
    print(f"resolver method: {summary['resolver_method']}")
    if summary.get("mx_records"):
        print(f"MX records: {', '.join(str(item) for item in summary['mx_records'])}")
    if summary.get("spf_records"):
        print(f"SPF records: {'; '.join(str(item) for item in summary['spf_records'])}")
    if summary.get("dmarc_records"):
        print(f"DMARC records: {'; '.join(str(item) for item in summary['dmarc_records'])}")
    if summary.get("validation_error"):
        print(f"validation error: {summary['validation_error']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
