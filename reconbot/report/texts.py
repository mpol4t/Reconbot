from __future__ import annotations

from typing import Any

# TODO(i18n): Introduce language selection and English translations.
# Current behavior intentionally keeps Turkish/default wording unchanged.
TR_TEXTS: dict[str, str] = {
    # Overview / lifecycle
    "overview_title": "Yönetici Özeti",
    "overview_intro": "Operatör görünümü: hızlı test kararları için yüksek sinyalli özet. Detaylı veri ilgili bölümlerde, tam dökümler ise Ham alanda bulunur.",
    "overview_label_risk": "Risk Skoru",
    "overview_label_decision_confidence": "Karar Güveni",
    "overview_label_top_surface": "En Öncelikli Yüzey",
    "overview_label_top_chain": "En Öncelikli Zincir",
    "overview_label_first_action": "İlk önerilen aksiyon",
    "overview_label_live_findings": "Canlı Bulgu Durumu",
    "overview_label_coverage_note": "Kapsama Notu",
    "overview_band_prefix": "Bant",
    "overview_no_dominant_driver": "Baskın risk sürücüsü yok.",
    "overview_top_surface_fallback": "Operasyonel etkisi en yüksek yüzey.",
    "overview_top_chain_confidence": "Güven",
    "overview_top_surface_priority": "Öncelik",
    "overview_coverage_structural_conf": "Rapor bütünlüğü",

    "operator_warning_strong": "Discovery kapsamı zayıfladı - bulgularla aksiyon almadan önce yüzeyi doğrula.",
    "operator_warning_discovery_failures": "Çalıştırma güvenilirliği discovery hataları nedeniyle zayıfladı ({failed_focus}).",
    "operator_warning_enrichment_failures": "Çalıştırma güvenilirliği zenginleştirme hataları nedeniyle zayıfladı ({failed_focus}).",
    "operator_warning_pipeline_failures": "Çalıştırma güvenilirliği pipeline hataları nedeniyle zayıfladı ({failed_focus}).",
    "operator_warning_pipeline_fallback": "pipeline zayıflaması",
    "operator_warning_tail": "Bulgular tüm saldırı yüzeyini temsil etmeyebilir. Exploit denemelerinden önce kapsama doğrulamasını önceliklendir.",

    "run_lifecycle_interrupted": '<p class="risk-note"><strong>Çalıştırma kullanıcı tarafından kesildi.</strong> Auto-refresh kapalı.</p>',
    "run_lifecycle_failed": '<p class="risk-note"><strong>Çalıştırma başarısız oldu.</strong> Auto-refresh kapalı.</p>',
    "run_lifecycle_completed": '<p class="note"><strong>Çalıştırma tamamlandı.</strong> Auto-refresh kapalı.</p>',
    "run_lifecycle_running": '<p class="live-note"><strong>Çalıştırma devam ediyor.</strong> Auto-refresh açık.</p>',

    "traffic_title": "Trafik Profili",
    "traffic_requested": "İstenen",
    "traffic_effective": "Etkin",
    "traffic_risk": "Risk",
    "traffic_recommended": "Önerilen sonraki çalışma",
    "traffic_events": "Auto throttle olayları:",
    "traffic_no_auto": "Auto throttle yok",

    # Discovery / pipeline
    "pipeline_table_missing": "Pipeline state verisi bulunamadı.",
    "pipeline_stage_note": "Bu tablo engine tarafından yazılan <code>run_result.json</code> içindeki stage verisini gösterir.",
    "pipeline_no_artifacts": "Artifact yok",

    # Nuclei state note snippets
    "nuclei_state_interrupted": '<p class="risk-note"><strong>Nuclei:</strong> run interrupted. Snapshot sabit kaldı; auto-refresh kapalı.</p>',
    "nuclei_state_live_snapshot": '<p class="live-note"><strong>Nuclei Findings (Live Snapshot):</strong> bulunan bulgular geçici olabilir; run tamamlandığında final durum güncellenecek.{extra}</p>',
    "nuclei_state_live": '<p class="live-note"><strong>Nuclei Findings (Live):</strong> tarama hâlâ çalışıyor olabilir. Bu rapor ilk snapshot olabilir.{extra}</p>',
    "nuclei_state_done_without_result": '<p class="note"><strong>Nuclei:</strong> stage tamam görünüyor ama CLI sonucu henüz bu rapora basmamış olabilir.</p>',
    "nuclei_state_error_with_value": '<p class="risk-note"><strong>Nuclei:</strong> stage hata ile bitmiş görünüyor. Hata: {error}</p>',
    "nuclei_state_error": '<p class="risk-note"><strong>Nuclei:</strong> stage hata ile bitmiş görünüyor. Log/output artifact yolunu kontrol et.</p>',
    "nuclei_state_no_result": '<p class="note"><strong>Nuclei:</strong> henüz sonuç yok.</p>',

    # Discovery sections
    "discovery_operator_note": "Özet-öncelikli discovery görünümü. Tam pipeline artifact ve ham çıktı bağlamı için blokları aç.",
    "discovery_pipeline_summary": "Pipeline Durumu / İlerleme",
    "discovery_nmap_summary": "Hızlı Nmap Taraması (İlk 1000 Port)",
    "discovery_nmap_empty": "(Nmap output boş / bu çalıştırmada atlanmış)",

    "gobuster_title": "Gobuster Sonuçları",
    "gobuster_note": "Önce özet görünüm. Temsili satırlar aşağıdadır; tüm path seviyesindeki inceleme Ham alanda kalır.",
    "gobuster_preview": "Gobuster bulguları önizlemesi",
    "gobuster_show_all": "Tüm Gobuster sonuçlarını göster",
    "gobuster_skipped": "Gobuster bu çalıştırmada <b>atlanmış</b> (config: gobuster.enabled=false).",
    "gobuster_empty": "Gobuster sonucu yok (ya çalışmadı ya da hiç base URL yok).",
    "gobuster_empty_short": "Gobuster sonucu yok.",

    "ffuf_title": "FFUF Sonuçları",
    "ffuf_note": "FFUF, canlı doğrulanmış HTTP(S) hedeflerinde path fuzzing yapar. Aşağıdaki bulgular endpoint analysis akışına da dahil edilir.",
    "ffuf_operator_note": "Operatör önizlemesi FFUF-only bulguları önceliklendirir. Tam eşleşme detayı Ham veri bölümlerinde erişilebilir kalır.",
    "ffuf_skipped": "FFUF bu çalıştırmada <b>atlanmış</b> (config/flag: ffuf_enabled=false).",
    "ffuf_empty": "FFUF sonucu yok (ya çalışmadı ya da hit üretmedi).",
    "ffuf_full_overlap": "FFUF bulguları Gobuster sonuçlarıyla tamamen örtüşüyor ({common} ortak bulgu).",
    "ffuf_partial_overlap": "{common} bulgu Gobuster ile örtüşüyor; aşağıda <strong>{unique}</strong> FFUF-only bulgu gösteriliyor.",
    "ffuf_preview": "FFUF-only bulgular önizlemesi",
    "ffuf_show_all": "Tüm FFUF-only bulguları göster",
    "ffuf_no_unique": "FFUF-only finding yok.",

    "waf_title": "🛡️ WAF / CDN Signals",
    "waf_note": "wafw00f çıktısından türetilen WAF/CDN sinyalleri. WAF varlığı exploit garantisi vermez; traffic profili ve rate-limit stratejisini etkiler. <strong>Tespit: {detected}</strong>",
    "waf_empty": "WAF/CDN sinyali verisi yok.",
    "waf_show_all": "Tüm WAF kayıtlarını göster",

    "whatweb_title": "🧪 WhatWeb Signals",
    "whatweb_note": "whatweb çıktısından teknoloji fingerprint zenginleştirmesi. Framework, middleware, panel ve servis ipuçları. <strong>Tespit: {detected}</strong>",
    "whatweb_empty": "WhatWeb sinyali verisi yok.",
    "whatweb_show_all": "Tüm WhatWeb kayıtlarını göster",

    # Correlation / suggestions / relationships
    "cve_enrichment_note": "NVD üzerinde best-effort keyword search. Kesin CPE eşleşmesi değil; manuel doğrulama gerektirir.",
    "cve_correlation_note": "CVE açıklamalarını keşfedilen saldırı yüzeyi ile ilişkilendirir; hangi yüzeyle daha anlamlı bağ kurulduğunu gösterir.",
    "cve_correlation_empty": "Ürün/sürüm fingerprint’i yeterli olmadığı için CVE adayı üretilmedi.",

    "suggestion_engine_title": "🧭 Bağlama Duyarlı Öneri Motoru",
    "suggestion_engine_note": "Öneriler operatör rehberliğidir, exploit kanıtı değildir. Confidence ve ton, görünürlük/güvenilirlik bağlamına göre otomatik ayarlanır.",
    "suggestion_engine_policy": "Policy: öneriler risk skoru, discovery güvenilirliği, karar güveni ve araç sağlığına göre ayarlanır.",
    "suggestion_engine_policy_critical": "CRITICAL güvenilirlik modu: yalnızca VALIDATION ve DISCOVERY_RECOVERY önerileri gösterilir.",
    "suggestion_engine_empty": "Bu sınırlı run’da URL seviyesinde aksiyon üretilecek doğrulanmış yüzey oluşmadı.",
    "suggestion_engine_preview": "Öneri önizlemesi",

    "node_relationships_title": "🧠 Node İlişkileri",
    "node_relationships_note": "Saldırı Grafiği node’ları için backend ilişki verisi. Grafik inceleyici bu veriyi node seviyesinde operatör bağlamı için kullanır.",
    "node_relationships_operator_note": "Varsayılan satırlar node etiketi, en önemli öneri ve CVE/tag/endpoint sayılarını tutar. Tam ilişki detayı için aç.",
    "node_relationships_preview": "Node ilişkileri önizlemesi",
    "node_relationships_empty": "Node ilişki verisi üretilmedi.",
    "node_relationships_show_all": "Tüm node ilişkilerini göster",

    # Risk / chains / priority
    "risk_engine_title": "📊 Risk Score Engine",
    "risk_engine_note": "ReconBot risk skoru, keşfedilen saldırı yüzeyi ve Nuclei bulgularını kullanarak operasyonel odağı önceliklendirir. Bu skor exploit kanıtı değildir; önceliklendirme sinyalidir.",

    "attack_chains_title": "🔗 Saldırı Zincirleri",
    "attack_chains_note": "Engine tarafından üretilen aday saldırı zincirleri. Onaylanmış zafiyet değildir; yalnızca operasyonel çıkarımdır. Zincirler: <strong>{count}</strong>",
    "attack_chains_low_reliability_tail": " | <span class='risk-note'>Confidence etkisi: {coverage_status}.{low_hint} Discovery kapsamı zayıfladı - bulgularla aksiyon almadan önce yüzeyi doğrula.</span>",
    "attack_chains_low_hint": " Tier-1 discovery hatası nedeniyle düşük güvenilirlik.",
    "attack_chains_supporting_tail": " | <span class='risk-note'>Destekleyici-stage etkisi: {coverage_status}.</span>",
    "attack_chains_empty": "Doğrulanmış yüzey veya bulgu olmadığı için saldırı zinciri kurulmadı.",
    "attack_chains_show_all": "Tüm zincirleri göster",

    "priority_engine_title": "🎯 Attack Priority Engine",
    "priority_engine_note": "Bu bölüm saldırı yüzeyini önceliklendirir. Amaç: \"önce nereyi test edeyim?\" sorusuna operasyonel bir başlangıç sırası vermek.",
    "priority_engine_empty": "Önceliklendirilecek güçlü bir saldırı yüzeyi sinyali üretilmedi.",
    "priority_nuclei_why": "Otomatik zafiyet bulguları doğrudan doğrulama adayıdır.",
    "priority_nuclei_test": "Template eşleşmelerini tek tek doğrula; false positive / exploitability kontrolü yap.",
    "priority_nuclei_surface_fallback": "Nuclei yüzey korelasyon sinyali.",
    "priority_nuclei_test_fallback": "Temsili kanıtı ve exploit path’i doğrula.",
    "priority_ffuf_why_fallback": "FFUF bulguları normalize scoring ile ele alınır.",
    "priority_ffuf_test_fallback": "FFUF representative endpointlerde yüksek değerli testleri önceliklendir.",
    "priority_upload_why": "Dosya yükleme yüzeyi RCE, parser abuse ve content-type bypass için yüksek değer taşır.",
    "priority_upload_test": "File upload bypass, extension/content-type spoofing, path traversal ve parser zincirlerini test et.",
    "priority_debug_why": "Debug/test rotaları config leak, internal feature ve zayıf koruma riski taşır.",
    "priority_debug_test": "Env/config leak, verbose error, test harness ve gizli parametreleri kontrol et.",
    "priority_admin_why": "Admin yüzeyi auth bypass, access control ve default credential testleri için kritiktir.",
    "priority_admin_test": "Role/access control, default creds, forced browsing ve auth bypass dene.",
    "priority_api_why": "API yüzeyi enumeration, mass assignment ve excessive data exposure için uygundur.",
    "priority_api_test": "Schema discovery, object-level auth, mass assignment ve excessive data exposure testleri yap.",
    "priority_docs_why": "Docs/dev sayfaları keşif, endpoint haritalama ve misconfiguration sinyali sağlar.",
    "priority_docs_test": "Swagger/docs içeriğinden gizli endpoint, örnek credential ve dev notlarını çıkar.",
    "priority_auth_why": "Auth yüzeyi (kanonik login/admin/xmlrpc/oauth aileleri) session ve workflow zayıflıkları için önemlidir.",
    "priority_auth_test": "Login akışını, reset/register/subflow'ları ve alternate giriş noktalarını (xmlrpc/oauth/SSO) birlikte incele.",

    # Raw / katana / auth / nuclei operator section
    "raw_title": "📂 Ham / Detaylı Veri",
    "raw_note": "<strong>Detaylı/ham inceleme alanı:</strong> Bu bölüm derin doğrulama için sıkıştırılmamış, kapsamlı çıktıları tutar. Diğer bölümler hızlı triyaj için düzenlenmiş özet/operatör görünümleridir.",

    "katana_skipped": "Katana bu çalıştırmada <b>atlanmış</b>.",
    "katana_empty": "Katana sonucu yok (ya çalışmadı ya da yeni endpoint bulamadı).",
    "katana_note": "endpoint_analysis ile temizlenmiş representative endpoint listesi. Varyantlar açılır alanda. <strong>{mode_text}</strong>",
    "katana_mode_clusters": "Cluster modu aktif.",
    "katana_mode_fallback": "Fallback: ham liste.",
    "katana_dense_note": "Bu, Katana temsilcilerinin detaylı/ham inceleme varyantıdır.",

    "auth_title": "Auth Yüzeyi / Login Flow Profiler",
    "auth_note": "Bu bölüm auth/login yüzeyini (login/register/reset/logout/xmlrpc/oauth/sso), captcha/CSRF sinyallerini, rate-limit/lockout ipuçlarını ve redirect davranışını profiler çıktısından özetler.",
    "auth_checks_skipped": "<strong>Web checks:</strong> bu çalıştırma sırasında atlanmış.",
    "auth_no_candidates": "Auth profiler bu çalıştırmada aday üretemedi (veya checks atlanmış/hata durumunda). Bu normal olabilir.",

    "nuclei_operator_note": "Nuclei auto-scan bulguları template ve severity odaklı operatör görünümünde özetlendi. Kesin zafiyet anlamına gelmez; doğrulama adımlarıyla teyit edilmelidir.",

    # Suggestion-generation strings (decision-safe layer)
    "suggestion_recover_tier1_title": "Exploit planlamasından önce Tier-1 discovery kapsamını toparla",
    "suggestion_recover_tier1_reasoning": "Tier-1 discovery araçları başarısız oldu ({tools}); saldırı yüzeyi confidence değeri sınırlanıyor.",
    "suggestion_recover_tier1_why": "Kritik discovery aracı hataları nedeniyle scan güvenilirliği zayıfladı. Önce kapsamı geri kazan.",
    "suggestion_recover_tier1_test_1": "katana/httpx’i stabil timeout ve retry ayarlarıyla yeniden çalıştır",
    "suggestion_recover_tier1_test_2": "Exploit öncesinde temsili endpoint envanterini doğrula",
    "suggestion_recover_tier1_test_3": "Discovery toparlandıktan sonra yüksek riskli path’leri yeniden değerlendir",
    "suggestion_recover_tier1_uncertainty": "Mevcut görünürlük zayıf; bulgular tüm saldırı yüzeyini temsil etmeyebilir.",
    "suggestion_low_conf_uncertainty": "Karar güveni LOW; öneri yön gösterici olarak ele alınmalı.",

    # Graph section / UI / inspector
    "graph_title": "🕸️ Saldırı Grafiği",
    "graph_note_1": "Operatör triyajı için ilişki haritası. Varsayılan görünüm; yüzeyler, bulgular, teknolojiler ve sonuçlar arasındaki yüksek değerli bağlantıları öne çıkarmak için sadeleştirilmiştir.",
    "graph_note_2": "Kapsamlı topoloji için <strong>Tam grafiği göster</strong> kullan. Grafik = ilişkiler, İnceleyici = neden önemli detayları, Ham tablolar = tam destekleyici veri.",
    "graph_meta_note": "Payload nodes/edges/paths: {nodes}/{edges}/{paths}",
    "graph_meta_note_empty": "Doğrulanmış yüzey veya bulgu olmadığı için saldırı zinciri kurulmadı.",
    "graph_scope_note": "Scope id: {scope}",
    "graph_scope_note_empty": "Scope id: -",
    "graph_best_reason_fallback": "Doğrulanmış yüzey veya bulgu olmadığı için saldırı zinciri kurulmadı.",
    "graph_best_score": "Strongest-path skoru: {rank} (base {base}/100 + kanıt artışı {boost}).",
    "graph_kpi_nodes_note": "Keşfedilen varlık etiketleri",
    "graph_kpi_edges_note": "Node-to-node ilişkiler",
    "graph_kpi_paths_note": "Belirlenen aday zincirler",
    "graph_raw_title": "Ham Grafik Verisi",
    "graph_raw_note": "Etkileşimli Cytoscape grafik UI’ını besleyen backend çıktısı.",

    "graph_ui_btn_fit": "Grafiği sığdır",
    "graph_ui_btn_reset_zoom": "Yakınlaştırmayı sıfırla",
    "graph_ui_btn_rerun_layout": "Yerleşimi yeniden çalıştır",
    "graph_ui_btn_show_full": "Tam grafiği göster",
    "graph_ui_btn_operator_view": "Operatör görünümü",
    "graph_ui_btn_fit": "Grafiği sığdır",
    "graph_ui_btn_reset_zoom": "Yakınlaştırmayı sıfırla",
    "graph_ui_btn_rerun_layout": "Yerleşimi yeniden çalıştır",
    "graph_ui_search_placeholder": "Node etiketine göre ara",
    "graph_ui_btn_search": "Ara",
    "graph_ui_filter_label": "Tüm node türleri",
    "graph_ui_min_confidence": "Minimum güven",
    "graph_ui_btn_highlight_path": "En güçlü yolu vurgula",
    "graph_ui_btn_clear_path": "En güçlü yol vurgusunu temizle",
    "graph_ui_btn_hide_low_signal": "Düşük sinyalli node’ları gizle",
    "graph_ui_btn_show_low_signal": "Düşük sinyalli node’ları göster",
    "graph_ui_helper_note": "Varsayılan operatör görünümüdür (ilişki odaklı). Kapsamlı topoloji için “Tam grafiği göster” kullan.",
    "graph_ui_initializing": "Etkileşimli grafik başlatılıyor...",
    "graph_ui_inspector_title": "İnceleyici",
    "graph_ui_inspector_note": "Detayları incelemek için bir node veya edge seç.",
    "graph_ui_init_failed_canvas": "Etkileşimli grafik başlatılamadı. Ham grafik veri tabloları aşağıda erişilebilir kalır.",
    "graph_ui_init_failed_inspector": "Etkileşimli grafik başlatılamadı. Ham grafik veri tabloları erişilebilir kalır.",
    "graph_ui_hint_no_node_data": "Grafik node verisi yok.",
    "graph_ui_hint_no_search_match": "Arama sorgusuyla eşleşen görünür node bulunamadı.",
    "graph_ui_hint_strongest_path": "En güçlü yol gerekçesi:",
    "graph_ui_library_missing_canvas": "Etkileşimli grafik kütüphanesi yüklenemedi. Grafik Veri Tabloları aşağıda erişilebilir kalır.",
    "graph_ui_library_missing_inspector": "Cytoscape.js yüklenmediği için etkileşimli grafik başlatılamadı.",
    "graph_ui_no_nodes_canvas": "Doğrulanmış yüzey veya bulgu olmadığı için saldırı zinciri kurulmadı.",
    "graph_ui_no_data_canvas": "Doğrulanmış yüzey veya bulgu olmadığı için saldırı zinciri kurulmadı.",
    "graph_ui_node_why_surface": "Bu, ilk manuel test sırasını değiştirebilecek açık bir giriş yüzeyidir.",
    "graph_ui_node_why_finding": "Bu node doğrudan Nuclei destekli kanıttır ve operatör güvenini etkilemelidir.",
    "graph_ui_node_why_outcome": "Bu node, üst kontroller aşılırsa oluşabilecek potansiyel etkiyi temsil eder.",
    "graph_ui_node_why_technology": "Bu teknoloji bağlamı exploit varsayımlarını ve payload stratejisini etkiler.",
    "graph_ui_node_why_support": "Bu node zincir ilişkilerine destekleyici bağlam sağlar.",
    "graph_ui_node_why_observed_count": "Gözlenen sinyal sayısı: {count}.",
    "graph_ui_node_why_observed_prefix": "Gözlenen sinyal sayısı: ",
    "graph_ui_node_why_observed_suffix": ".",
    "graph_ui_node_why_next_pivot": "Sonraki aksiyon odağı: {title}.",
    "graph_ui_node_why_next_pivot_prefix": "Sonraki aksiyon odağı: ",
    "graph_ui_node_why_next_pivot_suffix": ".",
    "graph_ui_node_why_cve": "Bağlı CVE bağlamı mevcut; bu path’e göre alakasını doğrula.",
    "graph_ui_node_why_tags": "Kanıt tag’leri/endpoint’leri mevcut; exploit önkoşullarını doğrulamak için kullan.",
    "graph_ui_edge_why_high": "Yol önceliklendirmesini güçlü biçimde destekleyen yüksek güvenli ilişki.",
    "graph_ui_edge_why_medium": "Orta güvenli ilişki; bitişik kanıtlarla doğrula.",
    "graph_ui_edge_why_low": "Düşük güvenli ilişki; doğrulanana kadar destekleyici çıkarım olarak ele al.",
}


REPORT_TEXTS = TR_TEXTS


def text(key: str, **kwargs: Any) -> str:
    value = REPORT_TEXTS.get(key, key)
    if kwargs:
        try:
            return value.format(**kwargs)
        except Exception:
            return value
    return value
