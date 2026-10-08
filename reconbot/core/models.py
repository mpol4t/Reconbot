# reconbot/core/models.py
from dataclasses import dataclass
from typing import Optional, Any

@dataclass
class Finding:
    tool: str
    name: str
    severity: str
    matched_at: str
    template_id: Optional[str] = None
    evidence: Optional[str] = None

def nuclei_to_findings(nuclei_results: Any) -> list[Finding]:
    """Convert various nuclei parse outputs into a normalized list of Finding objects."""

    events: list[Any] = []

    if nuclei_results is None:
        return []

    if isinstance(nuclei_results, list):
        events = nuclei_results
    elif isinstance(nuclei_results, dict):
        # common container keys
        for k in ("findings", "Findings", "results", "Results", "data", "Data"):
            v = nuclei_results.get(k)
            if isinstance(v, list):
                events = v
                break

        # sometimes parse output is a single event
        if not events and ("template-id" in nuclei_results or "templateID" in nuclei_results):
            events = [nuclei_results]
    else:
        return []

    out: list[Finding] = []

    for ev in events:
        if not isinstance(ev, dict):
            continue

        template_id = ev.get("template-id") or ev.get("templateID") or ev.get("id")
        info = ev.get("info") if isinstance(ev.get("info"), dict) else {}

        name = info.get("name") or ev.get("name") or template_id or "unknown"
        severity = info.get("severity") or ev.get("severity") or "unknown"
        matched_at = (
            ev.get("matched-at")
            or ev.get("matchedAt")
            or ev.get("host")
            or ev.get("url")
            or "unknown"
        )

        evidence_parts: list[str] = []
        if ev.get("type"):
            evidence_parts.append(f"type={ev.get('type')}")
        if ev.get("matcher-name") or ev.get("matcherName"):
            evidence_parts.append(f"matcher={ev.get('matcher-name') or ev.get('matcherName')}")
        if ev.get("extracted-results"):
            evidence_parts.append(f"extracted={ev.get('extracted-results')}")
        if ev.get("ip"):
            evidence_parts.append(f"ip={ev.get('ip')}")
        if ev.get("port"):
            evidence_parts.append(f"port={ev.get('port')}")

        evidence = "; ".join(evidence_parts) if evidence_parts else None

        out.append(
            Finding(
                tool="nuclei",
                name=str(name),
                severity=str(severity),
                matched_at=str(matched_at),
                template_id=str(template_id) if template_id else None,
                evidence=evidence,
            )
        )

    return out