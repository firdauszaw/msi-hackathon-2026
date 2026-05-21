"""Workflow orchestration for normal parse and AI parse runs."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Optional

from .docparser import safe_load_docx_mapping
from .env import load_env
from .llm import LLMManager
from .parser import LogParser
from .reporting import build_ai_markdown, build_normal_parse_markdown


DOC_REFERENCE_NAME = "1135099- MR2026.1_AT_Programmers_Guide_v1.docx"


class AnalysisWorkflow:
    def __init__(self, project_root: str):
        load_env(anchor_file=__file__)
        self.project_root = Path(project_root)
        self.outputs_dir = self.project_root / "outputs"
        self.outputs_dir.mkdir(parents=True, exist_ok=True)
        doc_path = self.project_root / DOC_REFERENCE_NAME
        self.cmd_map = safe_load_docx_mapping(str(doc_path)) if doc_path.exists() else {}
        self.llm = LLMManager()

    @staticmethod
    def _slugify(value: str) -> str:
        slug = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_")
        return slug or "case"

    def parse_log(self, log_path: str) -> Dict[str, Any]:
        parser = LogParser(log_path, cmd_map=self.cmd_map or None)
        report = parser.parse_report()
        return {
            "report": report,
            "overview_markdown": build_normal_parse_markdown(report),
        }

    def enrich_with_ai(self, report: Dict[str, Any]) -> Dict[str, Any]:
        result = self.llm.analyze_parse_report(report)
        result["markdown"] = build_ai_markdown(result)
        return result

    def save_outputs(
        self,
        source_path: str,
        report: Dict[str, Any],
        overview_markdown: str,
        ai_result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, str]:
        stem = self._slugify(Path(source_path).stem)
        paths = {
            "normal_json": str(self.outputs_dir / f"{stem}.normal.json"),
            "normal_md": str(self.outputs_dir / f"{stem}.normal.md"),
        }

        Path(paths["normal_json"]).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        Path(paths["normal_md"]).write_text(overview_markdown, encoding="utf-8")

        if ai_result is not None:
            paths.update(
                {
                    "ai_json": str(self.outputs_dir / f"{stem}.ai.json"),
                    "ai_md": str(self.outputs_dir / f"{stem}.ai.md"),
                    "ai_raw": str(self.outputs_dir / f"{stem}.ai.raw.txt"),
                }
            )
            Path(paths["ai_json"]).write_text(
                json.dumps(ai_result.get("parsed"), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            Path(paths["ai_md"]).write_text(ai_result.get("markdown", ""), encoding="utf-8")
            Path(paths["ai_raw"]).write_text(ai_result.get("raw", ""), encoding="utf-8")

        return paths