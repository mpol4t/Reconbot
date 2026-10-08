"""Optional SQLmap evidence section, independent of baseline scoring."""
from pathlib import Path
import html
import json


def render_sqlmap_validations(report_dir: Path) -> str:
    rows = []
    for file in sorted((Path(report_dir) / 'validations' / 'sqlmap').glob('*/result.json'), reverse=True):
        try:
            result = json.loads(file.read_text(encoding='utf-8'))
            status = result['status']
            if status == 'running':
                status = 'running / incomplete'
            esc = lambda value: html.escape(str(value))
            link = esc(str(file.parent.relative_to(report_dir) / 'report.html'))
            rows.append(f'<tr><td>{esc(result["url"])}</td><td>{esc(result["parameter"])}</td><td>{esc(status)}</td><td>{len(result.get("evidence", []))}</td><td><a href="{link}">Kanıt raporu</a></td></tr>')
        except (ValueError, KeyError, TypeError, OSError):
            continue
    if not rows:
        return ''
    return '<section id="sqlmap-validations" class="section"><h2>SQLmap doğrulama kanıtları</h2><p>Seçili parametreye yönelik bağımsız doğrulama işleri. Özgün tarama skoru değiştirilmez. Olumsuz sonuç yalnızca test edilen parametre ve teknikler için geçerlidir; yarım işler temiz sonuç değildir.</p><div style="overflow:auto"><table><thead><tr><th>URL</th><th>Parametre</th><th>Durum</th><th>Kanıt</th><th>Rapor</th></tr></thead><tbody>' + ''.join(rows) + '</tbody></table></div></section>'
