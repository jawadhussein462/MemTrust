"""A single self-contained HTML scan report.

Meant to be forwarded: summary numbers first, then each finding with the
record id, type, agreeing detectors, a masked snippet, the recommended
action, and the OWASP ASI06 reference.
"""

from __future__ import annotations

from datetime import UTC, datetime
from html import escape

from ..models.enums import Action, Severity
from ..models.results import ScanFinding, ScanReport
from .owasp import ASI06_REF, ASI06_URL

_LABELS: dict[str, str] = {
    "memory_poisoning": "Poisoned fact",
    "persistent_instruction": "Hidden instruction",
    "secret_detected": "Leaked secret",
    "pii_detected": "Personal data",
    "destination_redirect": "Destination redirect",
    "poisoning_cluster": "Poisoning cluster",
    "adversarial_text": "Adversarial text",
    "check_error": "Check error",
}

_ACTION_COPY: dict[Action, str] = {
    Action.REVIEW: "Review",
    Action.QUARANTINE: "Quarantine",
    Action.DELETE: "Delete",
    Action.BLOCK: "Delete",
}

_CSS = """
:root {
  --ink: #1c1917;
  --muted: #57534e;
  --line: #e7e5e4;
  --paper: #fafaf9;
  --card: #ffffff;
  --critical: #9f1239;
  --critical-bg: #fff1f2;
  --high: #c2410c;
  --high-bg: #fff7ed;
  --medium: #a16207;
  --medium-bg: #fefce8;
  --low: #57534e;
  --low-bg: #f5f5f4;
  --ok: #166534;
  --ok-bg: #f0fdf4;
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; background: var(--paper); color: var(--ink); }
body {
  font: 15px/1.5 "Iowan Old Style", "Palatino Linotype", Palatino, Georgia, serif;
}
.wrap { max-width: 920px; margin: 0 auto; padding: 40px 28px 72px; }
.kicker {
  font: 11px/1.2 ui-sans-serif, system-ui, sans-serif;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--muted);
}
h1 { font-size: 28px; line-height: 1.2; margin: 8px 0 6px; font-weight: 600; }
.lede { color: var(--muted); margin: 0 0 28px; max-width: 40em; }
.meta {
  font: 12px/1.4 ui-sans-serif, system-ui, sans-serif;
  color: var(--muted);
  margin-bottom: 28px;
}
.grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin: 0 0 28px; }
.tile {
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 16px 18px;
}
.tile .n { font: 600 28px/1.1 ui-sans-serif, system-ui, sans-serif; }
.tile .l {
  font: 11px/1.2 ui-sans-serif, system-ui, sans-serif;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--muted);
  margin-top: 6px;
}
.sev { display: flex; gap: 8px; flex-wrap: wrap; margin: 0 0 32px; }
.pill {
  font: 12px/1 ui-sans-serif, system-ui, sans-serif;
  border-radius: 999px;
  padding: 7px 10px;
  border: 1px solid var(--line);
  background: var(--card);
}
.pill b { font-weight: 650; }
h2 { font-size: 18px; margin: 8px 0 14px; }
.finding {
  background: var(--card);
  border: 1px solid var(--line);
  border-left-width: 4px;
  border-radius: 10px;
  padding: 16px 18px 14px;
  margin: 0 0 12px;
}
.finding.critical { border-left-color: var(--critical); }
.finding.high { border-left-color: var(--high); }
.finding.medium { border-left-color: var(--medium); }
.finding.low, .finding.info { border-left-color: var(--low); }
.head { display: flex; justify-content: space-between; gap: 12px; align-items: baseline; }
.title { font: 650 15px/1.3 ui-sans-serif, system-ui, sans-serif; }
.badge {
  font: 11px/1 ui-sans-serif, system-ui, sans-serif;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  padding: 5px 8px;
  border-radius: 6px;
}
.badge.critical { color: var(--critical); background: var(--critical-bg); }
.badge.high { color: var(--high); background: var(--high-bg); }
.badge.medium { color: var(--medium); background: var(--medium-bg); }
.badge.low, .badge.info { color: var(--low); background: var(--low-bg); }
.dl { display: grid; grid-template-columns: 140px 1fr; gap: 6px 12px; margin: 12px 0 0;
  font: 13px/1.45 ui-sans-serif, system-ui, sans-serif; }
.dl dt { color: var(--muted); }
.snippet {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12.5px;
  background: var(--paper);
  border-radius: 6px;
  padding: 8px 10px;
  overflow-wrap: anywhere;
}
.action { font-weight: 650; }
.empty { background: var(--ok-bg); color: var(--ok); border: 1px solid #bbf7d0;
  border-radius: 10px; padding: 16px 18px; }
.foot {
  margin-top: 36px; padding-top: 16px; border-top: 1px solid var(--line);
  font: 12px/1.5 ui-sans-serif, system-ui, sans-serif; color: var(--muted);
}
.foot a { color: inherit; }
@media (max-width: 700px) {
  .grid { grid-template-columns: 1fr; }
  .dl { grid-template-columns: 1fr; }
  .wrap { padding: 24px 16px 48px; }
}
@media print {
  body { background: white; }
  .finding { break-inside: avoid; }
}
""".strip()


def finding_label(code: str) -> str:
    return _LABELS.get(code, code.replace("_", " ").capitalize())


def render_html(report: ScanReport) -> str:
    """Return a standalone HTML document for ``report``."""
    when = report.generated_at or datetime.now(UTC)
    stamp = when.strftime("%Y-%m-%d %H:%M UTC")
    source = escape(report.source) if report.source else "memory store"
    sample = f" Sampled first {report.sample:,} records." if report.sample else ""
    pct = f"{report.flagged_pct:g}%"
    tiles = "".join(
        [
            _tile(f"{report.total:,}", "Records scanned"),
            _tile(f"{report.flagged:,}", "Records flagged"),
            _tile(pct, "Percentage flagged"),
        ]
    )
    sev_pills = _severity_pills(report)
    body = (
        _findings(report)
        if report.findings
        else (
            '<p class="empty">No poisoned facts, hidden instructions, or leaked secrets found.</p>'
        )
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>MemTrust scan report</title>
<style>{_CSS}</style>
</head>
<body>
<main class="wrap">
  <div class="kicker">MemTrust · local scan</div>
  <h1>Memory security report</h1>
  <p class="lede">
    Poisoned facts, hidden instructions, and leaked secrets in {source}.
    Generated locally — nothing left this machine.
  </p>
  <p class="meta">{escape(stamp)}.{sample} OWASP {escape(ASI06_REF)}.</p>
  <div class="grid">{tiles}</div>
  <div class="sev">{sev_pills}</div>
  <h2>Findings</h2>
  {body}
  <p class="foot">
    Recommended actions are <b>review</b>, <b>quarantine</b>, or <b>delete</b>.
    Reference:
    <a href="{escape(ASI06_URL)}">{escape(ASI06_REF)}</a>.
    Detectors that agree are listed per finding; snippets are masked.
  </p>
</main>
</body>
</html>
"""


def _tile(value: str, label: str) -> str:
    return (
        f'<div class="tile"><div class="n">{escape(value)}</div>'
        f'<div class="l">{escape(label)}</div></div>'
    )


def _severity_pills(report: ScanReport) -> str:
    if not report.findings:
        return '<span class="pill">Findings by severity · none</span>'
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    parts = ['<span class="pill">Findings by severity</span>']
    counts = report.by_severity
    for sev in order:
        n = counts.get(sev.value, 0)
        if n:
            parts.append(f'<span class="pill"><b>{n}</b> {escape(sev.value)}</span>')
    return "".join(parts)


def _findings(report: ScanReport) -> str:
    return "".join(_finding_card(item) for item in report.findings)


def _finding_card(item: ScanFinding) -> str:
    sev = item.severity.value
    label = finding_label(item.type)
    detectors = ", ".join(item.detectors) if item.detectors else "—"
    action = _ACTION_COPY.get(item.action, item.action.value.capitalize())
    return f"""
<article class="finding {escape(sev)}">
  <div class="head">
    <div class="title">{escape(label)} · {escape(item.id)}</div>
    <span class="badge {escape(sev)}">{escape(sev)}</span>
  </div>
  <dl class="dl">
    <dt>Finding type</dt><dd><code>{escape(item.type)}</code></dd>
    <dt>Detectors agreed</dt><dd>{escape(detectors)}</dd>
    <dt>Masked snippet</dt><dd class="snippet">{escape(item.snippet)}</dd>
    <dt>Recommended action</dt><dd class="action">{escape(action)}</dd>
    <dt>OWASP</dt><dd>{escape(item.owasp)}</dd>
  </dl>
</article>
"""


__all__ = ["finding_label", "render_html"]
