from __future__ import annotations

from typing import Any


def render_ip_enrichment_section(context: dict[str, Any]) -> str:
    _html_escape = context.get("_html_escape")
    _render_detail_value = context.get("_render_detail_value")
    report_base_url = str(context.get("report_base_url") or "")
    checks_results = context.get("checks_results") if isinstance(context.get("checks_results"), dict) else {}
    run_context = context.get("run_context") if isinstance(context.get("run_context"), dict) else {}

    ip_enrichment = run_context.get("ip_enrichment") if isinstance(run_context.get("ip_enrichment"), dict) else {}
    if not ip_enrichment and isinstance(checks_results, dict):
        ip_enrichment = checks_results.get("ip_enrichment") if isinstance(checks_results.get("ip_enrichment"), dict) else {}
    if not ip_enrichment:
        return ""

    raw_status = str(ip_enrichment.get("status") or "not_available").strip().lower()
    status = {"completed": "done", "failed": "error"}.get(raw_status, raw_status)

    original_target = str(ip_enrichment.get("original_target") or "-").strip() or "-"
    resolved_ip = str(ip_enrichment.get("resolved_ip") or "-").strip() or "-"
    hostname = str(ip_enrichment.get("hostname") or "-").strip() or "-"
    scan_mode = str(ip_enrichment.get("scan_mode") or "skipped").strip().lower() or "skipped"
    primary_nmap_reused = bool(ip_enrichment.get("already_covered_by_primary_nmap"))
    detailed = "yes" if bool(ip_enrichment.get("detailed_nmap_enabled")) else "no"
    started_at = str(ip_enrichment.get("started_at") or "-").strip() or "-"
    ended_at = str(ip_enrichment.get("ended_at") or "-").strip() or "-"
    note = str(ip_enrichment.get("note") or "").strip()
    error_text = str(ip_enrichment.get("error") or "").strip()
    risk_note = "Yardımcı bağlamdır; davranışsal zafiyet kanıtı olmadan risk skorunu yükseltmez."
    legacy_risk_note = "Auxiliary context only; does not increase risk without behavioral proof."

    results = ip_enrichment.get("results") if isinstance(ip_enrichment.get("results"), dict) else {}
    open_ports = results.get("open_ports") if isinstance(results.get("open_ports"), list) else []
    services = results.get("services") if isinstance(results.get("services"), list) else []
    probes = results.get("probes") if isinstance(results.get("probes"), list) else []

    mode_labels = {
        "already_covered": "already_covered",
        "lightweight": "Lightweight yardımcı kontroller",
        "quick": "Lightweight yardımcı kontroller",
        "detailed": "detailed_nmap",
        "detailed_nmap": "detailed_nmap",
        "skipped": "Atlandı",
    }
    mode_label = mode_labels.get(scan_mode, scan_mode or "-")
    status_labels = {
        "done": "Tamamlandı",
        "running": "Çalışıyor",
        "error": "Hata",
        "skipped": "Atlandı",
        "available_skipped": "Uygun / atlandı",
        "not_available": "Bilgi yok",
    }
    status_label = status_labels.get(status, status)

    if scan_mode == "already_covered" or primary_nmap_reused:
        mode_explanation = (
            "Bu IP, ana Nmap taraması sırasında zaten kontrol edilmişti. ReconBot aynı sonucu yardımcı IP bağlamı olarak rapora ekledi."
        )
    elif scan_mode in {"lightweight", "quick"}:
        mode_explanation = (
            "Lightweight IP enrichment yalnızca yardımcı probe kontrollerini çalıştırdı."
        )
    elif scan_mode in {"detailed", "detailed_nmap"}:
        mode_explanation = "Detailed Nmap yardımcı zenginleştirme olarak çalıştırıldı."
    elif status == "skipped":
        mode_explanation = "Operatör IP enrichment adımını atladı; primary URL/domain run kimliği değişmedi."
    else:
        mode_explanation = "IP enrichment sonucu auxiliary metadata olarak bu primary URL/domain run içine eklendi."

    if status == "error":
        state_explanation = f"IP enrichment hata ile bitti. {error_text}" if error_text else "IP enrichment hata ile bitti."
    elif status == "skipped":
        state_explanation = "IP enrichment atlandı; bu bölüm yalnızca operatör kararını ve çözümlenen IP bağlamını gösterir."
    elif status == "running":
        state_explanation = "IP enrichment çalışıyor; sonuç geldiğinde aynı run_result.json ve report.html güncellenir."
    elif status in {"available_skipped", "not_available"}:
        state_explanation = "IP enrichment metadata mevcut; bu bölüm çözümlenen IP bağlamını gösterir, zafiyet kanıtı değildir."
    else:
        state_explanation = "IP enrichment tamamlandı; port, servis ve probe sonuçları manuel doğrulama bağlamıdır, zafiyet kanıtı değildir."

    open_lines = [
        str(item.get("raw") or f"{item.get('port')}/{item.get('protocol', 'tcp')} open {item.get('service', '')} {item.get('detail', '')}").strip()
        for item in open_ports
        if isinstance(item, dict)
    ][:12]
    open_ports_html = (
        "<ul class='compact-list'>" + "".join(f"<li><code>{_html_escape(line)}</code></li>" for line in open_lines) + "</ul>"
        if open_lines
        else "<span class='note'>Açık port bilgisi yok veya bu modda port taraması çalışmadı.</span>"
    )

    service_lines = [
        " ".join(
            part
            for part in (
                f"{item.get('port')}/{item.get('protocol', 'tcp')}",
                str(item.get("service") or "").strip(),
                str(item.get("detail") or "").strip(),
            )
            if part
        )
        for item in services
        if isinstance(item, dict)
    ][:12]
    services_html = (
        "<ul class='compact-list'>" + "".join(f"<li><code>{_html_escape(line)}</code></li>" for line in service_lines) + "</ul>"
        if service_lines
        else "<span class='note'>Servis/version adayı yok; varsa manuel doğrulama gerektirir.</span>"
    )

    probe_lines = []
    for item in probes:
        if not isinstance(item, dict):
            continue
        probe = str(item.get("type") or item.get("probe") or "probe").strip()
        target = str(item.get("target") or item.get("url") or item.get("ip") or "").strip()
        status_value = str(item.get("status") or item.get("http_status") or item.get("status_code") or "").strip()
        note_value = str(item.get("note") or "").strip()
        if probe == "ptr":
            ptr_value = str(item.get("ptr") or "").strip()
            probe_lines.append(f"ptr: {target} status={status_value}{(' -> ' + ptr_value) if ptr_value else ''}")
            continue

        status_code = str(item.get("status_code") or item.get("http_status") or "").strip()
        server = str(item.get("server") or "").strip()
        location = str(item.get("location") or "").strip()
        detail_parts = [f"status={status_value or '-'}"]
        if status_code:
            detail_parts.append(f"code={status_code}")
        if server:
            detail_parts.append(f"server={server}")
        if location:
            detail_parts.append(f"location={location}")
        if note_value and status_value not in {"responded", "ok"}:
            detail_parts.append(note_value)
        probe_lines.append(f"{probe}: {target or '-'} {'; '.join(detail_parts)}")
    probe_lines = probe_lines[:12]
    probes_html = (
        "<ul class='compact-list'>" + "".join(f"<li><code>{_html_escape(line)}</code></li>" for line in probe_lines) + "</ul>"
        if probe_lines
        else "<span class='note'>PTR/direct IP/Host-header HTTP/TLS probe sonucu yok veya bu modda çalışmadı.</span>"
    )

    artifacts = ip_enrichment.get("artifacts") if isinstance(ip_enrichment.get("artifacts"), dict) else {}
    if not artifacts:
        artifacts = results.get("artifacts") if isinstance(results.get("artifacts"), dict) else {}
    tools_used = ip_enrichment.get("tools_used") if isinstance(ip_enrichment.get("tools_used"), list) else results.get("tools_used")
    tools_used_text = ", ".join(str(item) for item in tools_used) if isinstance(tools_used, list) and tools_used else "Yok"
    artifact_html = (
        "<ul class='compact-list'>"
        + "".join(f"<li><code>{_html_escape(str(name))}</code>: {_html_escape(str(value))}</li>" for name, value in artifacts.items())
        + "</ul>"
        if artifacts
        else "<span class='note'>Ek IP enrichment artifact referansı yok.</span>"
    )

    original_html = (
        _render_detail_value(original_target, report_base_url)
        if original_target.startswith(("http://", "https://", "/"))
        else _html_escape(original_target)
    )
    resolved_display = f"{hostname} -> {resolved_ip}" if hostname and hostname != "-" else resolved_ip

    return f"""
    <div class="section report-depth-body-all" data-depth-body="summary balanced deep" id="ip-enrichment" data-legacy-risk-note="{_html_escape(legacy_risk_note)}">
        <h2>IP Zenginleştirme</h2>
        <p class="note">Bu bölüm ana URL/domain run kimliğini değiştirmez. Çözümlenen IP yalnızca yardımcı bağlam olarak eklenir.</p>
        <p class="note"><strong>Mod:</strong> {_html_escape(mode_explanation)}</p>
        <p class="note"><strong>Durum:</strong> {_html_escape(state_explanation)}</p>
        <div class="ip-enrichment-report-grid">
            <div><span class="label">Orijinal hedef</span><strong>{original_html}</strong></div>
            <div><span class="label">Çözümlenen IP</span><strong>{_html_escape(resolved_display)}</strong></div>
            <div><span class="label">Mod</span><strong>{_html_escape(mode_label)}</strong></div>
            <div><span class="label">Durum</span><strong>{_html_escape(status_label)}</strong></div>
            <div><span class="label">Teknik ayrıntı</span><strong>{_html_escape(scan_mode)} / detailed_nmap={_html_escape(detailed)}</strong></div>
            <div><span class="label">Ana Nmap yeniden kullanımı</span><strong>{'Evet' if primary_nmap_reused else 'Hayır'}</strong></div>
            <div><span class="label">Zaman</span><strong>{_html_escape(started_at)} -> {_html_escape(ended_at)}</strong></div>
        </div>
        <p class="note report-depth-body-summary-only" data-depth-body="summary">
            IP bağlamı: {_html_escape(mode_label)} / {_html_escape(status_label)} / {len(open_ports)} açık port / {len(probes)} probe. {_html_escape(risk_note)}
        </p>
        <details class="show-more report-depth-body-balanced-deep" data-depth-body="balanced deep" open>
            <summary>IP enrichment kanıtları ve güvenlik notu</summary>
            <dl class="suggestion-detail ip-enrichment-detail">
                <dt>Açık portlar / servis adayları:</dt><dd>{open_ports_html}{services_html}</dd>
                <dt>Probe sonuçları:</dt><dd>{probes_html}</dd>
                <dt>Kullanılan araçlar:</dt><dd><code>{_html_escape(tools_used_text)}</code></dd>
                <dt>Artifact’lar:</dt><dd>{artifact_html}</dd>
                <dt>Not:</dt><dd>{_html_escape(note or "IP enrichment attached metadata olarak kaydedildi.")}</dd>
                <dt>Güvenlik notu:</dt><dd>{_html_escape(risk_note)}</dd>
            </dl>
        </details>
    </div>
    """
