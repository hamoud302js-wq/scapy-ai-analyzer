"""HTML report writer.

Everything derived from packet contents or model output is untrusted text and is
escaped with :func:`html.escape` before it reaches the document. Packet payload
bytes are never embedded: the report shows extracted fields only.

The four sections are visually distinct and explicitly labelled so a reader can
tell measured data from rule output, from AI interpretation, and from items that
still require human verification.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any, Optional

from ..models.session import AnalysisSession

STYLE = """
:root {
  --bg: #f5f6f8; --card: #ffffff; --ink: #1c2430; --muted: #5b6673;
  --border: #dde1e7; --observed: #2f6f4f; --rule: #9a6b1f; --ai: #3d5a9a;
  --review: #a33a3a; --code: #f0f2f5;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 24px; background: var(--bg); color: var(--ink);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  line-height: 1.55; font-size: 15px;
}
h1 { font-size: 22px; margin: 0 0 4px; }
h2 { font-size: 17px; margin: 28px 0 10px; padding-bottom: 6px; border-bottom: 2px solid var(--border); }
h3 { font-size: 15px; margin: 18px 0 6px; }
.wrap { max-width: 1100px; margin: 0 auto; }
.card {
  background: var(--card); border: 1px solid var(--border); border-radius: 8px;
  padding: 16px 18px; margin-bottom: 16px;
}
.muted { color: var(--muted); font-size: 13px; }
.tag {
  display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 11px;
  font-weight: 600; text-transform: uppercase; letter-spacing: .04em; color: #fff;
}
.tag-observed { background: var(--observed); }
.tag-rule { background: var(--rule); }
.tag-ai { background: var(--ai); }
.tag-review { background: var(--review); }
.sev { display: inline-block; padding: 1px 7px; border-radius: 4px; font-size: 11px;
       font-weight: 700; text-transform: uppercase; }
.sev-info { background: #e3e7ec; color: #39424e; }
.sev-low { background: #dcecd9; color: #2f6f4f; }
.sev-medium { background: #fbeccc; color: #8a5b12; }
.sev-high { background: #f8d8d3; color: #9c2f22; }
.sev-critical { background: #8a1c1c; color: #fff; }
table { width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 13px; }
th, td { text-align: left; padding: 7px 9px; border-bottom: 1px solid var(--border); vertical-align: top; }
th { background: var(--code); font-weight: 600; }
code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12.5px; }
code { background: var(--code); padding: 1px 5px; border-radius: 3px; }
pre { background: var(--code); padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 12.5px; }
ul { margin: 6px 0 6px 20px; padding: 0; }
li { margin: 3px 0; }
.kv { display: grid; grid-template-columns: minmax(160px, 220px) 1fr; gap: 4px 14px; font-size: 13.5px; }
.kv dt { color: var(--muted); }
.kv dd { margin: 0; }
.banner { border-left: 4px solid var(--ai); background: #eef2fa; padding: 10px 14px; border-radius: 4px; margin: 10px 0; }
.banner-warn { border-left-color: var(--review); background: #fdeeee; }
.section-note { font-size: 12.5px; color: var(--muted); margin: -4px 0 10px; }
.legend { display: flex; flex-wrap: wrap; gap: 14px; font-size: 12.5px; }
"""


def _e(value: Any) -> str:
    """Escape any value for safe HTML insertion."""
    if value is None:
        return '<span class="muted">not available</span>'
    return html.escape(str(value), quote=True)


def _severity_badge(severity: Optional[str]) -> str:
    sev = (severity or "info").lower()
    if sev not in ("info", "low", "medium", "high", "critical"):
        sev = "info"
    return f'<span class="sev sev-{sev}">{html.escape(sev)}</span>'


def _list(items: Optional[list], empty_text: str = "None reported.") -> str:
    if not items:
        return f'<p class="muted">{html.escape(empty_text)}</p>'
    rendered = "".join(f"<li>{_e(item)}</li>" for item in items)
    return f"<ul>{rendered}</ul>"


def render_html(session: AnalysisSession) -> str:
    """Render a session as a standalone HTML document."""
    stats = session.statistics or {}
    packet_totals = stats.get("packet_totals") or _packet_totals_from_stats(stats)
    ai = session.ai_analysis

    parts: list[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="en"><head><meta charset="utf-8">')
    parts.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    parts.append(f"<title>Scapy AI Analyzer report - {_e(session.session_id)}</title>")
    parts.append(f"<style>{STYLE}</style>")
    parts.append("</head><body><div class=\"wrap\">")

    # --- Header -------------------------------------------------------------
    parts.append('<div class="card">')
    parts.append("<h1>Scapy AI Analyzer - Analysis Report</h1>")
    parts.append(
        f'<p class="muted">Session <code>{_e(session.session_id)}</code> '
        f'&middot; generated {_e(session.started_at)}</p>'
    )
    parts.append('<div class="legend">')
    parts.append('<span><span class="tag tag-observed">Observed</span> measured from packets</span>')
    parts.append('<span><span class="tag tag-rule">Rule</span> deterministic rule output</span>')
    parts.append('<span><span class="tag tag-ai">AI</span> model interpretation</span>')
    parts.append('<span><span class="tag tag-review">Review</span> needs human verification</span>')
    parts.append("</div>")
    parts.append("</div>")

    # --- Run metadata -------------------------------------------------------
    parts.append('<div class="card">')
    parts.append('<h2 style="margin-top:0">Run information <span class="tag tag-observed">Observed</span></h2>')
    parts.append('<dl class="kv">')
    parts.append(f"<dt>Data source</dt><dd><code>{_e(session.source)}</code></dd>")
    parts.append(f"<dt>Source type</dt><dd>{_e(session.source_type)}</dd>")
    parts.append(f"<dt>Capture format</dt><dd>{_e(session.capture_format)}</dd>")
    parts.append(f"<dt>Packets analyzed</dt><dd>{_e(session.packet_count)}</dd>")
    parts.append(f"<dt>Packets with parse failures</dt><dd>{_e(session.packets_failed)}</dd>")
    parts.append(f"<dt>Analysis duration</dt><dd>{_e(round(session.duration_seconds, 3))} s</dd>")
    parts.append(f"<dt>Tool version</dt><dd>{_e(session.tool_version)}</dd>")
    parts.append(f"<dt>Report schema</dt><dd>{_e(session.schema_version)}</dd>")
    env = session.environment or {}
    if env:
        parts.append(f"<dt>Environment</dt><dd>{_e(json.dumps(env))}</dd>")
    parts.append("</dl>")
    parts.append("</div>")

    # --- Statistics ---------------------------------------------------------
    parts.append('<div class="card">')
    parts.append('<h2 style="margin-top:0">Traffic statistics <span class="tag tag-observed">Observed</span></h2>')
    parts.append('<div class="kv">')
    parts.append(f"<dt>Total packets</dt><dd>{_e(packet_totals.get('packets'))}</dd>")
    parts.append(f"<dt>Total bytes (captured)</dt><dd>{_e(packet_totals.get('bytes'))}</dd>")
    parts.append(f"<dt>Capture duration</dt><dd>{_e(packet_totals.get('duration_seconds'))} s</dd>")
    parts.append(f"<dt>Packets per second</dt><dd>{_e(packet_totals.get('packets_per_second'))}</dd>")
    parts.append(f"<dt>Parse status counts</dt><dd>{_e(json.dumps(stats.get('parse_status_counts', {})))}</dd>")
    parts.append("</div>")

    parts.append("<h3>Protocols observed</h3>")
    parts.append(_dict_table(stats.get("protocol_counts"), "Protocol", "Packets"))
    parts.append("<h3>Transport protocols</h3>")
    parts.append(_dict_table(stats.get("transport_counts"), "Transport", "Packets"))
    parts.append("<h3>Top destination ports</h3>")
    parts.append(_pairs_table(stats.get("top_dst_ports"), "Port", "Packets"))
    parts.append("<h3>Top source addresses</h3>")
    parts.append(_pairs_table(stats.get("top_src_ips"), "Source IP", "Packets"))
    if stats.get("tcp_flag_totals"):
        parts.append("<h3>TCP flag totals</h3>")
        parts.append(_dict_table(stats.get("tcp_flag_totals"), "Flag", "Count"))

    dns = stats.get("dns") or {}
    if dns:
        parts.append("<h3>DNS activity</h3>")
        parts.append('<dl class="kv">')
        parts.append(f"<dt>Queries</dt><dd>{_e(dns.get('queries'))}</dd>")
        parts.append(f"<dt>Responses</dt><dd>{_e(dns.get('responses'))}</dd>")
        parts.append(f"<dt>NXDOMAIN responses</dt><dd>{_e(dns.get('nxdomain'))}</dd>")
        parts.append("</dl>")
        if dns.get("top_queries"):
            parts.append("<h3>Most frequent DNS queries</h3>")
            parts.append(_pairs_table(dns.get("top_queries"), "Query", "Count"))

    if stats.get("host_volume_outliers"):
        parts.append("<h3>Host volume outliers</h3>")
        parts.append(
            '<p class="section-note">Statistical outliers within this capture only. '
            "This is a descriptive measurement, not a security verdict.</p>"
        )
        parts.append(_dict_table_from_list(stats["host_volume_outliers"], ["ip", "bytes", "zscore"]))
    parts.append("</div>")

    # --- Flows --------------------------------------------------------------
    parts.append('<div class="card">')
    parts.append('<h2 style="margin-top:0">Flows <span class="tag tag-observed">Observed</span></h2>')
    parts.append(
        f'<p class="section-note">{len(session.flows)} flow(s) recorded. '
        "A flow groups packets sharing endpoints and transport protocol.</p>"
    )
    if session.flows:
        rows = []
        for flow in session.flows[:200]:
            rows.append(
                "<tr>"
                f"<td><code>{_e(flow.get('flow_id'))}</code></td>"
                f"<td>{_e(flow.get('src_ip'))}:{_e(flow.get('src_port'))}</td>"
                f"<td>{_e(flow.get('dst_ip'))}:{_e(flow.get('dst_port'))}</td>"
                f"<td>{_e(flow.get('transport_protocol'))}</td>"
                f"<td>{_e(flow.get('total_packets'))}</td>"
                f"<td>{_e(flow.get('total_bytes'))}</td>"
                f"<td>{_e(round(flow.get('duration', 0), 3))}</td>"
                f"<td>{_e(json.dumps(flow.get('tcp_flag_counts', {})))}</td>"
                "</tr>"
            )
        parts.append(
            "<table><thead><tr><th>Flow</th><th>Source</th><th>Destination</th>"
            "<th>Proto</th><th>Packets</th><th>Bytes</th><th>Duration (s)</th><th>TCP flags</th>"
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
        )
        if len(session.flows) > 200:
            parts.append(
                f'<p class="muted">Showing the first 200 of {len(session.flows)} flows; '
                "the JSON report contains the full list.</p>"
            )
    else:
        parts.append('<p class="muted">No flows were formed from this capture.</p>')
    parts.append("</div>")

    # --- Alerts -------------------------------------------------------------
    parts.append('<div class="card">')
    parts.append(
        '<h2 style="margin-top:0">Rule alerts <span class="tag tag-rule">Rule</span></h2>'
    )
    parts.append(
        '<p class="section-note">Each alert states what was measured and what the rule '
        "cannot conclude. An alert is an indicator for review, not a confirmed incident.</p>"
    )
    if session.alerts:
        for alert in session.alerts:
            parts.append(f'<h3><code>{_e(alert.get("alert_id"))}</code> {_e(alert.get("rule_name"))} '
                         f'{_severity_badge(alert.get("severity"))}</h3>')
            parts.append('<dl class="kv">')
            parts.append(f"<dt>Rule</dt><dd><code>{_e(alert.get('rule_id'))}</code></dd>")
            parts.append(f"<dt>Description</dt><dd>{_e(alert.get('description'))}</dd>")
            parts.append(f"<dt>Why it fired</dt><dd>{_e(alert.get('reason'))}</dd>")
            parts.append(f"<dt>Source</dt><dd>{_e(alert.get('src_ip'))}</dd>")
            if alert.get("dst_ports"):
                ports = ", ".join(str(p) for p in alert["dst_ports"][:40])
                parts.append(f"<dt>Destination ports</dt><dd><code>{_e(ports)}</code></dd>")
            parts.append(f"<dt>Metrics</dt><dd><code>{_e(json.dumps(alert.get('metrics', {})))}</code></dd>")
            if alert.get("evidence_refs"):
                refs = ", ".join(str(r) for r in alert["evidence_refs"][:30])
                parts.append(f"<dt>Evidence references</dt><dd><code>{_e(refs)}</code></dd>")
            parts.append("</dl>")
            parts.append("<p><strong>Limitations of this alert</strong></p>")
            parts.append(_list(alert.get("limitations")))
    else:
        parts.append('<p class="muted">No rule alerts were raised for this capture.</p>')
    parts.append("</div>")

    # --- AI section ---------------------------------------------------------
    parts.append('<div class="card">')
    parts.append(
        '<h2 style="margin-top:0">AI interpretation <span class="tag tag-ai">AI</span></h2>'
    )
    parts.append(
        '<div class="banner">This section is model-generated interpretation of the data '
        "above. It is not measured fact and must be verified by a human before acting on it."
        "</div>"
    )
    if ai is None:
        parts.append('<p class="muted">AI analysis was not run.</p>')
    elif not ai.get("enabled"):
        parts.append('<p class="muted">AI analysis was disabled for this run (--no-ai).</p>')
        parts.append(
            '<p class="section-note">All statistics, flows, and rule alerts above were '
            "produced without AI and remain valid.</p>"
        )
    else:
        finding = ai.get("finding", {}) or {}
        status = finding.get("validation_status", "unknown")
        parts.append('<dl class="kv">')
        parts.append(f"<dt>Provider</dt><dd>{_e(ai.get('provider'))}</dd>")
        parts.append(f"<dt>Model</dt><dd>{_e(ai.get('model'))}</dd>")
        parts.append(f"<dt>Call succeeded</dt><dd>{_e(ai.get('succeeded'))}</dd>")
        parts.append(f"<dt>Validation status</dt><dd>{_e(status)}</dd>")
        parts.append(f"<dt>Duration</dt><dd>{_e(ai.get('duration_seconds'))} s</dd>")
        parts.append(f"<dt>Attempts</dt><dd>{_e(ai.get('attempts'))}</dd>")
        parts.append("</dl>")

        if not ai.get("succeeded"):
            parts.append('<div class="banner banner-warn">')
            parts.append("<strong>AI analysis did not produce a validated finding.</strong>")
            parts.append(_list(ai.get("errors"), "No error detail recorded."))
            parts.append("</div>")

        if finding.get("analysis_summary"):
            parts.append("<h3>Summary</h3>")
            parts.append(f'<p>{_e(finding.get("analysis_summary"))}</p>')

        parts.append("<h3>Finding</h3>")
        parts.append('<dl class="kv">')
        parts.append(f"<dt>Type</dt><dd>{_e(finding.get('finding_type'))}</dd>")
        parts.append(f"<dt>Severity</dt><dd>{_severity_badge(finding.get('severity'))}</dd>")
        confidence = finding.get("confidence")
        if confidence is None:
            parts.append("<dt>Confidence</dt><dd>not reported</dd>")
        else:
            parts.append(f"<dt>Confidence</dt><dd>{_e(confidence)}</dd>")
        parts.append("</dl>")
        if confidence is not None:
            parts.append(
                '<p class="section-note">'
                + _e(ai.get("confidence_disclaimer", "Confidence is a self-reported estimate."))
                + "</p>"
            )

        parts.append("<h3>Observations</h3>")
        parts.append(_list(finding.get("observations")))

        parts.append("<h3>Evidence references (verified against stored evidence)</h3>")
        if finding.get("evidence_refs"):
            refs = ", ".join(str(r) for r in finding["evidence_refs"])
            parts.append(f"<p><code>{_e(refs)}</code></p>")
        else:
            parts.append(
                '<p class="muted">No valid evidence references. The model either cited no '
                "references or cited references that do not exist in this session.</p>"
            )

        parts.append("<h3>Alternative explanations</h3>")
        parts.append(_list(finding.get("alternative_explanations")))

        parts.append("<h3>Limitations stated by the model</h3>")
        parts.append(_list(finding.get("limitations")))

        parts.append('<h3>Recommended next steps <span class="tag tag-review">Review</span></h3>')
        parts.append(_list(finding.get("recommended_next_steps")))

        warnings = list(ai.get("warnings") or []) + list(finding.get("validation_warnings") or [])
        if warnings:
            parts.append("<h3>Validation warnings</h3>")
            parts.append(_list(warnings))
    parts.append("</div>")

    # --- Errors / warnings / limitations ------------------------------------
    parts.append('<div class="card">')
    parts.append('<h2 style="margin-top:0">Errors, warnings, and limitations '
                 '<span class="tag tag-observed">Observed</span></h2>')
    parts.append("<h3>Errors</h3>")
    parts.append(_list(session.errors))
    parts.append("<h3>Warnings</h3>")
    parts.append(_list(session.warnings))
    parts.append("<h3>Analysis limitations</h3>")
    parts.append(_list(session.limitations))
    parts.append("</div>")

    # --- Configuration ------------------------------------------------------
    parts.append('<div class="card">')
    parts.append('<h2 style="margin-top:0">Configuration and reproducibility '
                 '<span class="tag tag-observed">Observed</span></h2>')
    parts.append(
        '<p class="section-note">Recorded so this analysis can be repeated. API keys are '
        "never included; only whether one was configured.</p>"
    )
    parts.append(f"<pre>{html.escape(json.dumps(session.configuration, indent=2, ensure_ascii=False, default=str))}</pre>")
    parts.append("</div>")

    parts.append('<p class="muted">Generated by Scapy AI Analyzer. '
                 "Packet fields are extracted with Scapy; AI output is interpretation only.</p>")
    parts.append("</div></body></html>")
    return "\n".join(parts)


def _packet_totals_from_stats(stats: dict) -> dict:
    return {
        "packets": stats.get("total_packets"),
        "bytes": stats.get("total_bytes"),
        "duration_seconds": round(stats.get("duration_seconds", 0), 3),
        "packets_per_second": stats.get("packets_per_second"),
    }


def _dict_table(mapping: Optional[dict], key_header: str, value_header: str) -> str:
    if not mapping:
        return '<p class="muted">No data.</p>'
    rows = "".join(
        f"<tr><td>{_e(key)}</td><td>{_e(value)}</td></tr>" for key, value in mapping.items()
    )
    return (
        f"<table><thead><tr><th>{html.escape(key_header)}</th><th>{html.escape(value_header)}</th>"
        f"</tr></thead><tbody>{rows}</tbody></table>"
    )


def _pairs_table(pairs: Optional[list], key_header: str, value_header: str) -> str:
    if not pairs:
        return '<p class="muted">No data.</p>'
    rows = []
    for item in pairs:
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            rows.append(f"<tr><td>{_e(item[0])}</td><td>{_e(item[1])}</td></tr>")
    return (
        f"<table><thead><tr><th>{html.escape(key_header)}</th><th>{html.escape(value_header)}</th>"
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table>"
    )


def _dict_table_from_list(items: list, keys: list[str]) -> str:
    if not items:
        return '<p class="muted">No data.</p>'
    header = "".join(f"<th>{html.escape(key)}</th>" for key in keys)
    rows = []
    for item in items:
        if not isinstance(item, dict):
            continue
        cells = "".join(f"<td>{_e(item.get(key))}</td>" for key in keys)
        rows.append(f"<tr>{cells}</tr>")
    return f"<table><thead><tr>{header}</tr></thead><tbody>{''.join(rows)}</tbody></table>"


def write_html_report(session: AnalysisSession, output_dir: str | Path) -> Path:
    """Write ``report.html`` into ``output_dir`` and return its path."""
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "report.html"
    path.write_text(render_html(session), encoding="utf-8")
    return path
