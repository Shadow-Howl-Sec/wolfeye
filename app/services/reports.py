"""Incident report generation."""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape

from app.models.alert import Alert


def build_incident_report(alert_id: int) -> bytes:
    alert = Alert.query.get(alert_id)
    if alert is None:
        raise ValueError(f"Alert with id={alert_id} not found")
    ioc = alert.ioc
    html = f"""<!doctype html><html><head><meta charset="utf-8">
    <style>body{{font-family:Arial;color:#18202a}}h1{{color:#7d1d1d}}
    table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #bbb;padding:8px;text-align:left}}</style>
    </head><body><h1>WolfEye Incident Report</h1>
    <p>Generated {datetime.now(timezone.utc).isoformat()}</p>
    <table><tr><th>Indicator</th><td>{escape(ioc.value)}</td></tr>
    <tr><th>Type</th><td>{escape(ioc.type)}</td></tr><tr><th>Source</th><td>{escape(ioc.source)}</td></tr>
    <tr><th>Severity</th><td>{escape(alert.severity)}</td></tr>
    <tr><th>Risk score</th><td>{(alert.risk_score if alert.risk_score is not None else alert.anomaly_score):.4f}</td></tr>
    <tr><th>Anomaly score</th><td>{alert.anomaly_score:.4f}</td></tr>
    <tr><th>Status</th><td>{escape(alert.status)}</td></tr></table>
    <h2>Analyst notes</h2><p>{escape(alert.notes or "None recorded.")}</p></body></html>"""
    try:
        from weasyprint import HTML
        return HTML(string=html).write_pdf()
    except (ImportError, OSError) as exc:
        # WeasyPrint needs GTK libraries on Windows; keep local development
        # usable while retaining WeasyPrint as the production renderer.
        import logging
        logging.getLogger(__name__).warning("WeasyPrint unavailable, using basic PDF renderer: %s", exc)
        score_value = alert.risk_score if alert.risk_score is not None else alert.anomaly_score
        return _basic_pdf([
            "WolfEye Incident Report",
            f"Indicator: {ioc.value}",
            f"Type: {ioc.type}  Source: {ioc.source}",
            f"Severity: {alert.severity}  Risk Score: {score_value:.4f}",
            f"Anomaly Score: {alert.anomaly_score:.4f}",
            f"Status: {alert.status}",
            f"Notes: {alert.notes or 'None recorded.'}",
        ])


def _basic_pdf(lines: list[str]) -> bytes:
    """Create a dependency-free, single-page PDF fallback."""
    text = "BT /F1 11 Tf 50 760 Td " + " ".join(
        f"({line.replace(chr(92), chr(92) * 2).replace('(', '\\(').replace(')', '\\)')}) Tj 0 -18 Td"
        for line in lines
    ) + " ET"
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        f"<< /Length {len(text.encode('latin-1', 'replace'))} >>\nstream\n{text}\nendstream".encode("latin-1", "replace"),
    ]
    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, 1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode())
        output.extend(obj)
        output.extend(b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode())
    output.extend("".join(f"{offset:010d} 00000 n \n" for offset in offsets[1:]).encode())
    output.extend(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF".encode())
    return bytes(output)
