"""Cloud-only LLM client for AI enrichment of deterministic parse reports."""

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


def _select_high_value_events(parse_report: Dict[str, Any], max_events: int = 36) -> list[Dict[str, Any]]:
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


def build_ai_enrichment_prompt(parse_report: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    context = {
        "summary": parse_report.get("summary"),
        "severity": parse_report.get("severity"),
        "stats": parse_report.get("stats", {}),
        "recommendations": parse_report.get("recommendations", []),
        "anomalies": parse_report.get("anomalies", [])[:12],
        "command_sessions": parse_report.get("command_sessions", [])[:20],
        "timeline_highlights": parse_report.get("timeline_highlights", [])[:20],
        "selected_events": _select_high_value_events(parse_report),
    }

    instructions = (
        "You are a cloud forensic assistant reviewing a deterministic UART/TETRA parse report. "
        "Do not re-parse raw logs. Use only the supplied structured report to infer likely causes, "
        "operator actions, and forensic narrative.\n\n"
        "Return valid JSON between <<<JSON>>> and <<<END_JSON>>>. After <<<END_JSON>>> you may add a concise markdown report.\n\n"
        "Required JSON schema:\n"
        "<<<JSON>>>\n"
        "{\n"
        "  \"executive_summary\": \"string\",\n"
        "  \"root_causes\": [\n"
        "    {\"title\": \"string\", \"confidence\": 0.0, \"reasoning\": \"string\", \"supporting_evidence\": [\"string\"]}\n"
        "  ],\n"
        "  \"priority_actions\": [\"string\"],\n"
        "  \"forensic_narrative\": [\"string\"],\n"
        "  \"operator_questions\": [\"string\"],\n"
        "  \"severity\": \"low|medium|high\"\n"
        "}\n"
        "<<<END_JSON>>>\n\n"
        "Rules:\n"
        "- Keep evidence references specific and tie them to line numbers when present.\n"
        "- Prefer 2-4 root causes, not a long list.\n"
        "- If certainty is limited, reduce confidence instead of inventing facts.\n"
        "- Avoid repeating every parser anomaly verbatim; synthesize them into a useful case narrative.\n\n"
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
            raise RuntimeError("RFBOX_API_KEY is required for AI enrichment")

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
        max_tokens: int = 1600,
        temperature: float = 0.2,
        timeout: int = 120,
    ) -> Dict[str, Any]:
        prompt, context = build_ai_enrichment_prompt(parse_report)
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
