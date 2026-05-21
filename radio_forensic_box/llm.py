"""Cloud-only LLM client for AI flow analysis of deterministic parse reports."""

from __future__ import annotations

import json
import os
import re
import threading
from typing import Any, Callable, Dict, Optional, Tuple

DEFAULT_API_MODEL = "VertexGemini"
DEFAULT_API_ENDPOINT = "https://genai-service.stage.commandcentral.com/app-gateway/api/v2/chat"


def _sanitize_json_string(value: str) -> str:
    cleaned = re.sub(r",\s*([}\]])", r"\1", value)
    cleaned = re.sub(r"[\x00-\x1f]", "", cleaned)
    return cleaned


def _clean_markdown_tail(value: str) -> str:
    cleaned = (value or "").strip()
    cleaned = cleaned.replace("<<<END_JSON>>>", "").strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.I)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    return cleaned.strip()


def _salvage_ai_parse_object(raw_candidate: str, fallback_severity: Optional[str] = None) -> Optional[Dict[str, Any]]:
    if not raw_candidate:
        return None

    ordered_keys = [
        "flow_summary",
        "flow_steps_review",
        "suspect_flow_segments",
        "likely_root_causes",
        "recommended_checks",
        "forensic_narrative",
        "severity",
        "executive_summary",
        "root_causes",
        "priority_actions",
        "operator_questions",
    ]

    salvaged: Dict[str, Any] = {}
    for index, key in enumerate(ordered_keys):
        key_match = re.search(rf'"{re.escape(key)}"\s*:\s*', raw_candidate)
        if not key_match:
            continue

        value_start = key_match.end()
        next_positions = []
        for later_key in ordered_keys[index + 1 :]:
            next_match = re.search(rf'\n\s*"{re.escape(later_key)}"\s*:', raw_candidate[value_start:])
            if next_match:
                next_positions.append(value_start + next_match.start())

        value_end = min(next_positions) if next_positions else len(raw_candidate)
        value_text = raw_candidate[value_start:value_end].strip().rstrip(",").strip()
        if not value_text:
            continue

        try:
            salvaged[key] = json.loads(value_text)
            continue
        except Exception:
            pass

        if value_text.startswith("["):
            array_text = value_text
            last_object_end = array_text.rfind("}")
            if last_object_end != -1:
                try:
                    salvaged[key] = json.loads(array_text[: last_object_end + 1] + "]")
                    continue
                except Exception:
                    pass

        if value_text.startswith('"'):
            tail = value_text.rfind('"')
            if tail > 0:
                try:
                    salvaged[key] = json.loads(value_text[: tail + 1])
                    continue
                except Exception:
                    pass

    if not salvaged:
        return None

    if "severity" not in salvaged and fallback_severity:
        salvaged["severity"] = fallback_severity

    return salvaged


def extract_json_block(text: str) -> Tuple[Optional[Dict[str, Any]], str]:
    start_marker = "<<<JSON>>>"
    end_marker = "<<<END_JSON>>>"
    start = text.find(start_marker)
    end = text.find(end_marker)
    if start != -1 and end != -1 and end > start:
        raw = text[start + len(start_marker) : end].strip()
        try:
            parsed = json.loads(raw)
        except Exception as exc:
            parsed = {"_parse_error": str(exc), "raw": raw}
        return parsed, _clean_markdown_tail(text[end + len(end_marker) :])

    candidate_region = text[:end] if end != -1 else text
    brace_start = candidate_region.find("{")
    brace_end = candidate_region.rfind("}")
    if brace_start != -1 and brace_end != -1 and brace_end > brace_start:
        raw = candidate_region[brace_start : brace_end + 1]
        try:
            parsed = json.loads(raw)
        except Exception as exc:
            parsed = {"_parse_error": str(exc), "raw": raw}

        if end != -1:
            markdown = text[end + len(end_marker) :]
        else:
            markdown = text[brace_end + 1 :]
        return parsed, _clean_markdown_tail(markdown)

    match = re.search(r"\{[\s\S]*\}", text or "", flags=re.S)
    if match:
        raw = match.group(0)
        try:
            parsed = json.loads(raw)
        except Exception as exc:
            parsed = {"_parse_error": str(exc), "raw": raw}
        markdown = (text or "").replace(raw, "", 1)
        return parsed, _clean_markdown_tail(markdown)

    return None, _clean_markdown_tail(text)


def _select_high_value_events(parse_report: Dict[str, Any], max_events: int = 18) -> list[Dict[str, Any]]:
    selected: list[Dict[str, Any]] = []
    events = parse_report.get("events", [])
    for event in events:
        tags = set(event.get("tags", []))
        if tags or event.get("event_type") in {"command", "response"}:
            selected.append(
                {
                    "line": event.get("line"),
                    "timestamp": event.get("timestamp"),
                    "message": event.get("message"),
                    "massaged": event.get("massaged"),
                    "event_type": event.get("event_type"),
                    "command": event.get("command"),
                    "tags": event.get("tags", []),
                }
            )
        if len(selected) >= max_events:
            break
    return selected


def _select_key_sessions(parse_report: Dict[str, Any], max_sessions: int = 10) -> list[Dict[str, Any]]:
    sessions = parse_report.get("command_sessions", [])
    selected: list[Dict[str, Any]] = []

    for session in sessions:
        should_keep = (
            session.get("problem_hint")
            or session.get("response_status") in {"error", "timeout"}
            or session.get("command") in {"CFUN", "ATR", "CMGS", "ATI"}
        )
        if not should_keep:
            continue
        selected.append(
            {
                "id": session.get("id"),
                "command": session.get("command"),
                "command_line": session.get("command_line"),
                "response_end_line": session.get("response_end_line"),
                "response_status": session.get("response_status"),
                "human_command": session.get("human_command"),
                "human_response": session.get("human_response"),
                "problem_hint": session.get("problem_hint"),
                "response_preview": session.get("response_preview"),
            }
        )
        if len(selected) >= max_sessions:
            break

    return selected


def _build_command_comparisons(parse_report: Dict[str, Any]) -> list[Dict[str, Any]]:
    grouped: dict[str, list[Dict[str, Any]]] = {}
    for session in parse_report.get("command_sessions", []):
        command = session.get("command")
        if not command:
            continue
        grouped.setdefault(command, []).append(session)

    comparisons: list[Dict[str, Any]] = []
    for command, sessions in grouped.items():
        statuses = {item.get("response_status") for item in sessions}
        if len(statuses) < 2:
            continue

        comparisons.append(
            {
                "command": command,
                "healthy_examples": [
                    {
                        "id": item.get("id"),
                        "command_line": item.get("command_line"),
                        "response_status": item.get("response_status"),
                        "response_preview": item.get("response_preview"),
                    }
                    for item in sessions
                    if item.get("response_status") in {"ok", "data"}
                ][:2],
                "problem_examples": [
                    {
                        "id": item.get("id"),
                        "command_line": item.get("command_line"),
                        "response_status": item.get("response_status"),
                        "problem_hint": item.get("problem_hint"),
                        "response_preview": item.get("response_preview"),
                    }
                    for item in sessions
                    if item.get("response_status") in {"error", "timeout"} or item.get("problem_hint")
                ][:3],
            }
        )

    return comparisons[:4]


def _select_problem_windows(parse_report: Dict[str, Any], radius: int = 2, max_windows: int = 6) -> list[Dict[str, Any]]:
    events_by_line = {event.get("line"): event for event in parse_report.get("events", [])}
    windows: list[Dict[str, Any]] = []
    for anomaly in parse_report.get("anomalies", [])[:max_windows]:
        start = max(1, anomaly.get("start_line", 1) - radius)
        end = anomaly.get("end_line", anomaly.get("start_line", 1)) + radius
        rows = []
        for line in range(start, end + 1):
            event = events_by_line.get(line)
            if not event:
                continue
            rows.append(
                {
                    "line": event.get("line"),
                    "message": event.get("message"),
                    "tags": event.get("tags", []),
                    "event_type": event.get("event_type"),
                }
            )
        windows.append(
            {
                "anomaly_id": anomaly.get("id"),
                "title": anomaly.get("title"),
                "lines": [anomaly.get("start_line"), anomaly.get("end_line")],
                "window": rows,
            }
        )
    return windows


def build_ai_parse_prompt(parse_report: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    flow_steps = parse_report.get("flow_steps", [])
    focus_steps = [step for step in flow_steps if step.get("outcome") != "normal"] or flow_steps[:8]
    context = {
        "summary": parse_report.get("summary"),
        "human_summary": parse_report.get("human_summary"),
        "severity": parse_report.get("severity"),
        "stats": parse_report.get("stats", {}),
        "parser_recommendations": parse_report.get("recommendations", []),
        "flow_steps": focus_steps[:10],
        "anomalies": parse_report.get("anomalies", [])[:8],
        "key_sessions": _select_key_sessions(parse_report),
        "command_comparisons": _build_command_comparisons(parse_report),
        "problem_windows": _select_problem_windows(parse_report, max_windows=4),
        "selected_events": _select_high_value_events(parse_report),
    }

    instructions = (
        "You are a cloud forensic assistant reviewing a deterministic UART/TETRA parse report. "
        "Your main job is to explain the operational flow in plain language and identify exactly where that flow starts to go wrong. "
        "Do not re-parse the raw file from scratch and do not produce generic telecom advice unless the evidence supports it.\n\n"
        "Return valid JSON between <<<JSON>>> and <<<END_JSON>>>. After <<<END_JSON>>> you may add a concise markdown report.\n\n"
        "Required JSON schema:\n"
        "<<<JSON>>>\n"
        "{\n"
        "  \"flow_summary\": \"string\",\n"
        "  \"flow_steps_review\": [\n"
        "    {\"title\": \"string\", \"lines\": [1, 2], \"status\": \"ok|watch|problem\", \"reason\": \"string\"}\n"
        "  ],\n"
        "  \"suspect_flow_segments\": [\n"
        "    {\"title\": \"string\", \"lines\": [1, 2], \"problem\": \"string\", \"why_it_matters\": \"string\", \"confidence\": 0.0, \"evidence\": [\"string\"]}\n"
        "  ],\n"
        "  \"likely_root_causes\": [\n"
        "    {\"title\": \"string\", \"confidence\": 0.0, \"reasoning\": \"string\", \"evidence\": [\"string\"]}\n"
        "  ],\n"
        "  \"recommended_checks\": [\"string\"],\n"
        "  \"forensic_narrative\": [\"string\"],\n"
        "  \"severity\": \"low|medium|high\"\n"
        "}\n"
        "<<<END_JSON>>>\n\n"
        "Rules:\n"
        "- Keep evidence references specific and tie them to exact lines or parser ids when present.\n"
        "- Focus first on the flow and its breakpoints, then on root causes.\n"
        "- Compare successful and failed steps when the same command appears in both states.\n"
        "- If certainty is limited, reduce confidence instead of inventing facts.\n"
        "- Avoid generic phrases like 'check the network' unless you can explain why a specific step suggests it.\n\n"
        "Structured parse report:\n"
    )

    prompt = instructions + json.dumps(context, indent=2, ensure_ascii=False)
    return prompt, context


class LLMManager:
    def __init__(
        self,
        api_key: Optional[str] = None,
        api_model: Optional[str] = None,
        api_base: Optional[str] = None,
    ):
        self.api_key = api_key or os.environ.get("RFBOX_API_KEY")
        self.api_model = api_model or os.environ.get("RFBOX_API_MODEL", DEFAULT_API_MODEL)
        base = api_base or os.environ.get("RFBOX_API_BASE")
        if base and not base.endswith("/api/v2/chat"):
            base = base.rstrip("/") + "/api/v2/chat"
        self.api_base = base or DEFAULT_API_ENDPOINT

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    def update_config(
        self,
        api_key: Optional[str] = None,
        api_model: Optional[str] = None,
        api_base: Optional[str] = None,
    ) -> None:
        if api_key is not None:
            self.api_key = api_key.strip()
        if api_model is not None and api_model.strip():
            self.api_model = api_model.strip()
        if api_base is not None and api_base.strip():
            base = api_base.strip()
            self.api_base = base if base.endswith("/api/v2/chat") else base.rstrip("/") + "/api/v2/chat"

    def generate_sync(self, prompt: str, max_tokens: int = 1600, temperature: float = 0.2, timeout: int = 120) -> str:
        if not self.api_key:
            raise RuntimeError("RFBOX_API_KEY is required for AI Parse")

        try:
            import requests
        except Exception as exc:
            raise RuntimeError("requests import failed: " + str(exc)) from exc

        headers = {
            "x-msi-genai-api-key": self.api_key,
            "Content-Type": "application/json",
        }
        payload = {
            "userId": None,
            "model": self.api_model,
            "prompt": prompt,
            "system": "",
            "modelConfig": {
                "temperature": temperature,
                "max_tokens": max_tokens,
            },
        }

        response = requests.post(self.api_base, headers=headers, json=payload, timeout=timeout)
        response.raise_for_status()

        try:
            wrapper = response.json()
        except Exception:
            return response.text

        if isinstance(wrapper, dict) and isinstance(wrapper.get("msg"), str):
            return wrapper["msg"]
        return json.dumps(wrapper, ensure_ascii=False)

    def generate_async(
        self,
        prompt: str,
        callback: Callable[[str], None],
        status_callback: Optional[Callable[[str], None]] = None,
        max_tokens: int = 1600,
        temperature: float = 0.2,
        timeout: int = 120,
    ) -> None:
        def _worker() -> None:
            try:
                if status_callback:
                    status_callback("Calling cloud AI...")
                response_text = self.generate_sync(
                    prompt,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    timeout=timeout,
                )
                callback(response_text)
                if status_callback:
                    status_callback("Cloud AI complete")
            except Exception as exc:
                if status_callback:
                    status_callback(f"Cloud AI error: {exc}")
                callback(f"Cloud AI error: {exc}")

        threading.Thread(target=_worker, daemon=True).start()

    def analyze_parse_report(
        self,
        parse_report: Dict[str, Any],
        max_tokens: int = 1200,
        temperature: float = 0.1,
        timeout: int = 90,
    ) -> Dict[str, Any]:
        prompt, context = build_ai_parse_prompt(parse_report)
        raw_text = self.generate_sync(prompt, max_tokens=max_tokens, temperature=temperature, timeout=timeout)
        parsed, markdown = extract_json_block(raw_text)

        if parsed is None or (isinstance(parsed, dict) and parsed.get("_parse_error")):
            raw_candidate = None
            if isinstance(parsed, dict):
                raw_candidate = parsed.get("raw")
            if raw_candidate:
                try:
                    parsed = json.loads(_sanitize_json_string(raw_candidate))
                except Exception as exc:
                    salvaged = _salvage_ai_parse_object(raw_candidate, fallback_severity=parse_report.get("severity"))
                    if salvaged:
                        parsed = salvaged
                    else:
                        parsed = {
                            "_parse_error": f"sanitization_failed: {exc}",
                            "raw": raw_candidate,
                        }

        return {
            "parsed": parsed,
            "markdown": markdown,
            "raw": raw_text,
            "prompt": prompt,
            "context": context,
        }


if __name__ == "__main__":
    print("Cloud-only LLM manager: use analyze_parse_report(report).")
