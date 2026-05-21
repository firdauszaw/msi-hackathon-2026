"""Deterministic parser for UART AT-command logs.

The parser is intentionally non-AI and produces a structured forensic report that
can be shown directly in the UI and optionally sent to cloud AI for enrichment.
"""

from __future__ import annotations

from datetime import datetime
import re
from typing import Any, Dict, List, Optional, Tuple


DEFAULT_CMD_MAP = {
    "CTSDC": "Call setup or data channel command",
    "MCMCO": "MC management command",
    "CTSP": "TETRA service parameter query",
    "CREG": "Network registration status",
    "CTBCT": "Broadcast control channel info",
    "CMGS": "Send message command",
    "CFUN": "Radio functional state control",
}


class LogParser:
    """Parses raw UART logs into deterministic forensic structures."""

    HEX_RE = re.compile(r"(?:0x[0-9A-Fa-f]{16,}|\b[A-Fa-f0-9]{32,}\b)")
    TS_RE = re.compile(r"^\[?(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[\.,]\d+)?)\]?\s*(?P<body>.*)$")
    NON_ASCII_RE = re.compile(r"[^\x09\x0A\x0D\x20-\x7E]")
    COMMAND_RE = re.compile(r"(?:AT\+|\+)(?P<cmd>[A-Z0-9]{2,12})", re.I)
    CREATED_CMD_RE = re.compile(r"(?:New command created|Continue for last command):\s*\+?(?P<cmd>[A-Z0-9]{2,12})", re.I)
    RESPONSE_RE = re.compile(r"^\+?(?P<cmd>[A-Z0-9]{2,12})\s*:\s*(?P<payload>.*)$", re.I)
    ERROR_RE = re.compile(r"\b(?:ERROR|FAIL|PANIC|\+CME\s+ERROR|\+CMS\s+ERROR)\b", re.I)

    def __init__(self, filepath: str, cmd_map: Optional[Dict[str, str]] = None):
        self.filepath = filepath
        self.cmd_map = cmd_map or DEFAULT_CMD_MAP

    def read_raw_lines(self) -> List[str]:
        with open(self.filepath, "r", encoding="utf-8", errors="ignore") as file_handle:
            return [line.rstrip("\n\r") for line in file_handle]

    def _parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        raw = (ts_str or "").replace(",", ".")
        try:
            return datetime.fromisoformat(raw)
        except Exception:
            pass
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(raw, fmt)
            except Exception:
                continue
        return None

    def _extract_timestamp_and_body(self, line: str) -> Tuple[Optional[datetime], str]:
        match = self.TS_RE.match(line)
        if not match:
            return None, line.strip()

        ts = self._parse_timestamp(match.group("ts"))
        body = match.group("body").strip()
        if "|" in body:
            parts = [part.strip() for part in body.split("|") if part.strip()]
            if parts:
                body = parts[-1]
        body = re.sub(r"^\d{2}/", "", body).strip()
        return ts, body

    def _extract_command(self, message: str) -> Optional[str]:
        if not message:
            return None

        created_match = self.CREATED_CMD_RE.search(message)
        if created_match:
            return created_match.group("cmd").upper()

        direct_match = self.COMMAND_RE.search(message)
        if direct_match:
            return direct_match.group("cmd").upper()

        return None

    def _massage_line(self, message: str, command: Optional[str]) -> str:
        massaged = self.HEX_RE.sub("[HEX PAYLOAD STRIPPED]", message)
        massaged = re.sub(r"\s+", " ", massaged).strip()
        if command and command in self.cmd_map:
            massaged = f"{massaged} // {self.cmd_map[command]}"
        return massaged

    def _classify_event(self, message: str, command: Optional[str]) -> Tuple[str, List[str], Dict[str, Any]]:
        tags: List[str] = []
        details: Dict[str, Any] = {}
        lowered = message.lower()

        if not message:
            return "blank", tags, details

        if self.NON_ASCII_RE.search(message):
            tags.append("non_ascii")

        if self.ERROR_RE.search(message):
            tags.append("error")

        if command and message.lower().startswith(("at+", "new command created", "continue for last command")):
            event_type = "command"
        elif message.upper() == "OK":
            event_type = "response"
            details["status"] = "ok"
        elif "ERROR" in message.upper():
            event_type = "response"
            details["status"] = "error"
        elif self.RESPONSE_RE.match(message):
            event_type = "response"
            details["status"] = "data"
        else:
            event_type = "event"

        if "+CREG:" in message.upper() and re.search(r"\+CREG\s*:\s*0\b", message, re.I):
            tags.append("registration_drop")

        if "CFUN=0" in message.upper() or message.upper().startswith("ATR"):
            tags.append("radio_reinit")

        if "SERIAL PORT" in lowered and "OPEN" in lowered:
            tags.append("serial_open")

        if "+CTBCT:" in message.upper():
            tags.append("channel_state")

        return event_type, tags, details

    def _pair_command_responses(self, events: List[Dict[str, Any]], lookahead: int = 8) -> List[Dict[str, Any]]:
        sessions: List[Dict[str, Any]] = []
        session_counter = 1

        for index, event in enumerate(events):
            if event["event_type"] != "command" or not event.get("command"):
                continue

            response_event = None
            for next_index in range(index + 1, min(index + 1 + lookahead, len(events))):
                candidate = events[next_index]
                if candidate["event_type"] != "response":
                    continue
                response_event = candidate
                break

            latency_ms = None
            status = "timeout"
            if response_event is not None:
                status = response_event.get("details", {}).get("status", "data")
                if event.get("ts") and response_event.get("ts"):
                    latency_ms = int((response_event["ts"] - event["ts"]).total_seconds() * 1000)
                    if latency_ms > 300:
                        response_event["tags"].append("latency_spike")

            if response_event is None:
                event["tags"].append("missing_response")

            sessions.append(
                {
                    "id": f"cmd-{session_counter:04d}",
                    "command": event.get("command"),
                    "command_line": event["line"],
                    "command_text": event["message"],
                    "response_line": response_event["line"] if response_event else None,
                    "response_text": response_event["message"] if response_event else None,
                    "response_status": status,
                    "latency_ms": latency_ms,
                }
            )
            session_counter += 1

        return sessions

    def _detect_long_gaps(self, events: List[Dict[str, Any]], threshold_seconds: int = 10) -> List[Dict[str, Any]]:
        anomalies: List[Dict[str, Any]] = []
        for idx in range(1, len(events)):
            previous = events[idx - 1]
            current = events[idx]
            if not previous.get("ts") or not current.get("ts"):
                continue
            gap_seconds = (current["ts"] - previous["ts"]).total_seconds()
            if gap_seconds > threshold_seconds:
                anomalies.append(
                    {
                        "type": "time_gap",
                        "severity": "medium",
                        "title": f"Large log gap ({gap_seconds:.2f}s)",
                        "start_line": previous["line"],
                        "end_line": current["line"],
                        "details": {
                            "gap_seconds": round(gap_seconds, 3),
                            "previous": previous["message"],
                            "current": current["message"],
                        },
                    }
                )
        return anomalies

    def _detect_command_flooding(self, sessions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        anomalies: List[Dict[str, Any]] = []
        if not sessions:
            return anomalies

        streak_command = sessions[0]["command"]
        streak_start = 0
        for idx in range(1, len(sessions) + 1):
            is_break = idx == len(sessions) or sessions[idx]["command"] != streak_command
            if not is_break:
                continue

            streak_len = idx - streak_start
            if streak_command and streak_len >= 4:
                anomalies.append(
                    {
                        "type": "command_flooding",
                        "severity": "medium",
                        "title": f"Repeated command burst: {streak_command}",
                        "start_line": sessions[streak_start]["command_line"],
                        "end_line": sessions[idx - 1]["command_line"],
                        "details": {
                            "command": streak_command,
                            "count": streak_len,
                            "session_ids": [s["id"] for s in sessions[streak_start:idx]],
                        },
                    }
                )

            if idx < len(sessions):
                streak_command = sessions[idx]["command"]
                streak_start = idx

        return anomalies

    def _build_anomalies(self, events: List[Dict[str, Any]], sessions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        anomalies: List[Dict[str, Any]] = []
        anomaly_counter = 1

        for event in events:
            if "non_ascii" in event["tags"]:
                anomalies.append(
                    {
                        "id": f"an-{anomaly_counter:04d}",
                        "type": "garbled_data",
                        "severity": "medium",
                        "title": "Non-ASCII payload detected",
                        "start_line": event["line"],
                        "end_line": event["line"],
                        "details": {"raw": event["raw"]},
                    }
                )
                anomaly_counter += 1

            if "error" in event["tags"]:
                anomalies.append(
                    {
                        "id": f"an-{anomaly_counter:04d}",
                        "type": "error_response",
                        "severity": "high",
                        "title": "Error response observed",
                        "start_line": event["line"],
                        "end_line": event["line"],
                        "details": {"message": event["message"]},
                    }
                )
                anomaly_counter += 1

            if "registration_drop" in event["tags"]:
                anomalies.append(
                    {
                        "id": f"an-{anomaly_counter:04d}",
                        "type": "registration_drop",
                        "severity": "medium",
                        "title": "Network registration dropped",
                        "start_line": event["line"],
                        "end_line": event["line"],
                        "details": {"message": event["message"]},
                    }
                )
                anomaly_counter += 1

            if "radio_reinit" in event["tags"]:
                anomalies.append(
                    {
                        "id": f"an-{anomaly_counter:04d}",
                        "type": "radio_reinit",
                        "severity": "medium",
                        "title": "Radio reinitialization sequence",
                        "start_line": event["line"],
                        "end_line": event["line"],
                        "details": {"message": event["message"]},
                    }
                )
                anomaly_counter += 1

        for session in sessions:
            if session["response_status"] == "timeout":
                anomalies.append(
                    {
                        "id": f"an-{anomaly_counter:04d}",
                        "type": "missing_response",
                        "severity": "high",
                        "title": "Command missing response",
                        "start_line": session["command_line"],
                        "end_line": session["command_line"],
                        "details": {
                            "command": session["command"],
                            "session_id": session["id"],
                        },
                    }
                )
                anomaly_counter += 1

            if session.get("latency_ms") and session["latency_ms"] > 300:
                anomalies.append(
                    {
                        "id": f"an-{anomaly_counter:04d}",
                        "type": "latency_spike",
                        "severity": "medium",
                        "title": "Slow command response latency",
                        "start_line": session["command_line"],
                        "end_line": session["response_line"] or session["command_line"],
                        "details": {
                            "command": session["command"],
                            "latency_ms": session["latency_ms"],
                            "session_id": session["id"],
                        },
                    }
                )
                anomaly_counter += 1

        extra_anomalies = self._detect_long_gaps(events) + self._detect_command_flooding(sessions)
        for anomaly in extra_anomalies:
            anomaly["id"] = f"an-{anomaly_counter:04d}"
            anomaly_counter += 1
            anomalies.append(anomaly)

        return anomalies

    def _recommendations(self, anomalies: List[Dict[str, Any]]) -> List[str]:
        types = {item["type"] for item in anomalies}
        recommendations: List[str] = []

        if "missing_response" in types:
            recommendations.append("Inspect UART flow-control and increase command timeout for missing command responses.")
        if "error_response" in types:
            recommendations.append("Review AT command prerequisites and retry sequence around ERROR or +CME ERROR lines.")
        if "registration_drop" in types:
            recommendations.append("Check RF coverage, SIM provisioning, and registration retry policy for repeated +CREG: 0 events.")
        if "command_flooding" in types:
            recommendations.append("Throttle repeated polling commands to avoid command flooding and unstable modem behavior.")
        if "garbled_data" in types:
            recommendations.append("Validate UART baud rate, parity, and encoding to eliminate garbled non-ASCII payloads.")

        if not recommendations:
            recommendations.append("No critical anomalies detected. Continue monitoring and keep current command cadence.")

        return recommendations

    @staticmethod
    def _severity_from_anomalies(anomalies: List[Dict[str, Any]]) -> str:
        rank = {"low": 1, "medium": 2, "high": 3}
        worst = 1
        for anomaly in anomalies:
            worst = max(worst, rank.get(anomaly.get("severity", "low"), 1))
        reverse = {1: "low", 2: "medium", 3: "high"}
        return reverse.get(worst, "low")

    def parse_report(self) -> Dict[str, Any]:
        """Create deterministic forensic JSON for the full log."""
        raw_lines = self.read_raw_lines()
        events: List[Dict[str, Any]] = []

        for line_number, raw in enumerate(raw_lines, start=1):
            ts, message = self._extract_timestamp_and_body(raw)
            command = self._extract_command(message)
            massaged = self._massage_line(message, command)
            event_type, tags, details = self._classify_event(message, command)

            events.append(
                {
                    "line": line_number,
                    "timestamp": ts.isoformat() if ts else None,
                    "ts": ts,
                    "raw": raw,
                    "message": message,
                    "massaged": massaged,
                    "event_type": event_type,
                    "command": command,
                    "tags": tags,
                    "details": details,
                }
            )

        sessions = self._pair_command_responses(events)
        anomalies = self._build_anomalies(events, sessions)
        severity = self._severity_from_anomalies(anomalies)

        stats = {
            "total_lines": len(events),
            "commands": sum(1 for event in events if event["event_type"] == "command"),
            "responses": sum(1 for event in events if event["event_type"] == "response"),
            "errors": sum(1 for event in events if "error" in event["tags"]),
            "missing_responses": sum(1 for session in sessions if session["response_status"] == "timeout"),
            "non_ascii_lines": sum(1 for event in events if "non_ascii" in event["tags"]),
            "registration_drops": sum(1 for event in events if "registration_drop" in event["tags"]),
        }

        summary = (
            f"Parsed {stats['total_lines']} lines with {stats['commands']} commands and "
            f"{stats['responses']} responses. Detected {len(anomalies)} anomalies "
            f"({stats['errors']} error lines, {stats['missing_responses']} missing responses)."
        )

        report_events = []
        for event in events:
            report_events.append(
                {
                    "line": event["line"],
                    "timestamp": event["timestamp"],
                    "raw": event["raw"],
                    "message": event["message"],
                    "massaged": event["massaged"],
                    "event_type": event["event_type"],
                    "command": event["command"],
                    "tags": event["tags"],
                    "details": event["details"],
                }
            )

        timeline_highlights = []
        for anomaly in anomalies[:20]:
            timeline_highlights.append(
                {
                    "line": anomaly["start_line"],
                    "type": anomaly["type"],
                    "title": anomaly["title"],
                    "severity": anomaly["severity"],
                }
            )

        return {
            "metadata": {
                "source_file": self.filepath,
                "parsed_at": datetime.utcnow().isoformat() + "Z",
            },
            "summary": summary,
            "severity": severity,
            "stats": stats,
            "recommendations": self._recommendations(anomalies),
            "command_sessions": sessions,
            "anomalies": anomalies,
            "timeline_highlights": timeline_highlights,
            "events": report_events,
        }

    def parse(self) -> List[Dict[str, Any]]:
        """Compatibility adapter for older callers expecting parsed line entries."""
        report = self.parse_report()
        parsed: List[Dict[str, Any]] = []
        for event in report["events"]:
            parsed.append(
                {
                    "raw": event["raw"],
                    "ts": self._parse_timestamp(event["timestamp"]) if event["timestamp"] else None,
                    "body": event["message"],
                    "massaged": event["massaged"],
                    "idx": event["line"],
                    "tags": event["tags"],
                }
            )
        return parsed

    def get_sliding_window(self, parsed: List[Dict[str, Any]], window_size: int = 50) -> List[Dict[str, Any]]:
        for index in range(len(parsed) - 1, -1, -1):
            if re.search(r"\bERROR\b|\bFAIL\b|\bRESET\b", parsed[index]["body"], flags=re.I):
                start = max(0, index - window_size)
                return parsed[start : index + 1]
        return parsed[max(0, len(parsed) - window_size) :]

    def detect_anomalies(self, window: List[Dict[str, Any]]) -> Dict[str, Any]:
        missing = [entry for entry in window if "missing_response" in entry.get("tags", [])]
        flooding: List[List[Dict[str, Any]]] = []

        if window:
            streak_start = 0
            for index in range(1, len(window) + 1):
                is_break = index == len(window) or window[index]["massaged"] != window[index - 1]["massaged"]
                if not is_break:
                    continue

                streak_size = index - streak_start
                if streak_size >= 4:
                    flooding.append(window[streak_start:index])
                if index < len(window):
                    streak_start = index

        return {"missing_responses": missing, "command_flooding": flooding}


if __name__ == "__main__":
    print("LogParser module: use parse_report() for deterministic forensic output.")
