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


def _format_line_range(lines: Any) -> str:
    if isinstance(lines, list) and lines:
        if len(lines) == 1:
            return f"L{lines[0]}"
        return f"L{lines[0]}-{lines[-1]}"
    return "line unknown"


def build_normal_parse_markdown(report: Dict[str, Any]) -> str:
    stats = report.get("stats", {})
    anomalies = report.get("anomalies", [])
    sessions = report.get("command_sessions", [])
    recommendations = report.get("recommendations", [])
    flow_steps = report.get("flow_steps", [])

    lines: List[str] = []
    lines.append("# Normal Parse Review")
    lines.append(report.get("human_summary", report.get("summary", "No summary available.")))
    lines.append("")
    lines.append("## Case Severity")
    lines.append(report.get("severity", "unknown").upper())
    lines.append("")
    lines.append("## What The Parser Saw")
    lines.append(f"- Total lines: {stats.get('total_lines', 0)}")
    lines.append(f"- Commands: {stats.get('commands', 0)}")
    lines.append(f"- Responses: {stats.get('responses', 0)}")
    lines.append(f"- Error lines: {stats.get('errors', 0)}")
    lines.append(f"- Missing responses: {stats.get('missing_responses', 0)}")
    lines.append(f"- Registration drops: {stats.get('registration_drops', 0)}")
    lines.append("")
    lines.append("## Plain-English Flow")
    if flow_steps:
        for index, step in enumerate(flow_steps, start=1):
            lines.append(
                f"{index}. {_format_line_range(step.get('lines'))}: {step.get('title', 'Untitled step')}"
            )
            lines.append(f"   {step.get('explanation', '')}")
    else:
        lines.append("- The parser could not build a step-by-step flow for this log.")
    lines.append("")
    lines.append("## Where The Flow Looks Wrong")
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
    lines.append("## Decoded AT Command Flow")
    if sessions:
        for session in sessions[:12]:
            latency = session.get("latency_ms")
            latency_text = f", latency={latency}ms" if latency is not None else ""
            lines.append(
                f"- L{session.get('command_line')}-{session.get('response_end_line') or session.get('response_line') or session.get('command_line')} "
                f"{session.get('command')} -> {session.get('response_status')}" + latency_text
            )
            lines.append(f"  Host action: {session.get('human_command', '')}")
            lines.append(f"  Parser reading: {session.get('human_response', '')}")
            if session.get("problem_hint"):
                lines.append(f"  Problem hint: {session.get('problem_hint')}")
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
    parsed = (ai_result or {}).get("parsed")
    if not isinstance(parsed, dict):
        return "No AI report available."

    lines: List[str] = []
    lines.append("# AI Parse Review")
    lines.append(parsed.get("flow_summary") or parsed.get("executive_summary", "No AI summary available."))
    lines.append("")
    lines.append("## Flow Steps That Look Wrong")
    suspect_segments = parsed.get("suspect_flow_segments") or []
    if suspect_segments:
        for segment in suspect_segments:
            lines.append(
                f"- {_format_line_range(segment.get('lines'))}: {segment.get('title', 'Suspicious segment')} "
                f"(confidence={segment.get('confidence', 'n/a')})"
            )
            lines.append(f"  Problem: {segment.get('problem', '')}")
            lines.append(f"  Impact: {segment.get('why_it_matters', '')}")
    else:
        review_steps = parsed.get("flow_steps_review") or []
        if review_steps:
            for step in review_steps:
                if step.get("status") not in {"watch", "problem"}:
                    continue
                lines.append(
                    f"- {_format_line_range(step.get('lines'))}: {step.get('title', 'Flow step')} [{step.get('status')}]"
                )
                lines.append(f"  {step.get('reason', '')}")
        else:
            lines.append("- AI did not identify a specific broken flow segment.")
    lines.append("")
    lines.append("## Likely Causes")
    causes = parsed.get("likely_root_causes") or parsed.get("root_causes") or []
    if causes:
        for cause in causes:
            lines.append(
                f"- {cause.get('title', 'Untitled')} "
                f"(confidence={cause.get('confidence', 'n/a')}): {cause.get('reasoning', '')}"
            )
    else:
        lines.append("- No likely causes returned.")
    lines.append("")
    lines.append("## Recommended Checks")
    actions = parsed.get("recommended_checks") or parsed.get("priority_actions") or []
    if actions:
        for action in actions:
            lines.append(f"- {action}")
    else:
        lines.append("- No actions returned.")
    narrative = parsed.get("forensic_narrative") or []
    if narrative:
        lines.append("")
        lines.append("## AI Flow Read")
        for item in narrative:
            lines.append(f"- {item}")
    return "\n".join(lines)