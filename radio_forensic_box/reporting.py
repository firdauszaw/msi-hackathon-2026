"""Formatting helpers for deterministic and AI forensic outputs."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple


def _short_detail(details: Dict[str, Any]) -> str:
    if not details:
        return ""
    for key in ("message", "command", "raw", "gap_seconds"):
        value = details.get(key)
        if value is not None:
            return f"{key}: {value}"
    return json.dumps(details, ensure_ascii=False)


def build_normal_parse_markdown(report: Dict[str, Any]) -> str:
    stats = report.get("stats", {})
    anomalies = report.get("anomalies", [])
    sessions = report.get("command_sessions", [])
    recommendations = report.get("recommendations", [])

    lines: List[str] = []
    lines.append("# Case Overview")
    lines.append(report.get("summary", "No summary available."))
    lines.append("")
    lines.append("## Severity")
    lines.append(report.get("severity", "unknown").upper())
    lines.append("")
    lines.append("## Quick Stats")
    lines.append(f"- Total lines: {stats.get('total_lines', 0)}")
    lines.append(f"- Commands: {stats.get('commands', 0)}")
    lines.append(f"- Responses: {stats.get('responses', 0)}")
    lines.append(f"- Error lines: {stats.get('errors', 0)}")
    lines.append(f"- Missing responses: {stats.get('missing_responses', 0)}")
    lines.append(f"- Registration drops: {stats.get('registration_drops', 0)}")
    lines.append("")
    lines.append("## Key Findings")
    if anomalies:
        for anomaly in anomalies[:12]:
            detail = _short_detail(anomaly.get("details", {}))
            base = (
                f"- [{anomaly.get('severity', 'low').upper()}] "
                f"L{anomaly.get('start_line')} {anomaly.get('title')} ({anomaly.get('type')})"
            )
            lines.append(base if not detail else f"{base} :: {detail}")
    else:
        lines.append("- No anomalies detected by the deterministic parser.")
    lines.append("")
    lines.append("## Command Sessions")
    if sessions:
        for session in sessions[:12]:
            latency = session.get("latency_ms")
            latency_text = f", latency={latency}ms" if latency is not None else ""
            lines.append(
                f"- L{session.get('command_line')} {session.get('command')} -> "
                f"{session.get('response_status')}" + latency_text
            )
    else:
        lines.append("- No command sessions detected.")
    lines.append("")
    lines.append("## Recommendations")
    for item in recommendations:
        lines.append(f"- {item}")
    return "\n".join(lines)


def build_anomaly_panel_text(report: Dict[str, Any]) -> str:
    anomalies = report.get("anomalies", [])
    if not anomalies:
        return "No anomalies detected."

    lines: List[str] = []
    for anomaly in anomalies[:20]:
        lines.append(
            f"{anomaly.get('id')} | {anomaly.get('severity', 'low').upper()} | "
            f"L{anomaly.get('start_line')}-{anomaly.get('end_line')} | {anomaly.get('title')}"
        )
        detail = _short_detail(anomaly.get("details", {}))
        if detail:
            lines.append(f"  {detail}")
        lines.append("")
    return "\n".join(lines).strip()


def build_timeline_rows(report: Dict[str, Any]) -> List[Tuple[str, str]]:
    rows: List[Tuple[str, str]] = []
    for event in report.get("events", []):
        timestamp = event.get("timestamp") or "--"
        text = f"{event.get('line', 0):04d} | {timestamp} | {event.get('massaged', '')}"
        tags = set(event.get("tags", []))
        if "error" in tags:
            style = "error"
        elif {"missing_response", "latency_spike", "registration_drop", "radio_reinit"} & tags:
            style = "warning"
        elif event.get("event_type") == "blank":
            style = "meta"
        else:
            style = "normal"
        rows.append((text, style))
    return rows


def build_ai_markdown(ai_result: Dict[str, Any]) -> str:
    markdown = (ai_result or {}).get("markdown") or ""
    if markdown.strip():
        return markdown

    parsed = (ai_result or {}).get("parsed")
    if not isinstance(parsed, dict):
        return "No AI report available."

    lines: List[str] = []
    lines.append("# AI Forensic Enrichment")
    lines.append(parsed.get("executive_summary", "No executive summary available."))
    lines.append("")
    lines.append("## Root Causes")
    causes = parsed.get("root_causes") or []
    if causes:
        for cause in causes:
            lines.append(
                f"- {cause.get('title', 'Untitled')} "
                f"(confidence={cause.get('confidence', 'n/a')}): {cause.get('reasoning', '')}"
            )
    else:
        lines.append("- No root causes returned.")
    lines.append("")
    lines.append("## Priority Actions")
    actions = parsed.get("priority_actions") or []
    if actions:
        for action in actions:
            lines.append(f"- {action}")
    else:
        lines.append("- No actions returned.")
    return "\n".join(lines)