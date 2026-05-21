"""Desktop UI for Radio Forensic Box.

Workflow:
1. Load a UART AT log file.
2. Run Normal Parse for deterministic analysis.
3. Optionally run AI Enrich, which sends the deterministic report to cloud AI.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import threading
import tkinter as tk
from tkinter import filedialog, scrolledtext

import customtkinter as ctk

from .env import load_env, resolve_project_root
from .reporting import build_ai_markdown, build_anomaly_panel_text, build_timeline_rows
from .workflow import AnalysisWorkflow


class RadioForensicApp:
    def __init__(self, root=None):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.root = root or ctk.CTk()
        self.root.title("Radio Forensic Box")
        self.root.geometry("1380x860")
        self.root.minsize(1200, 760)

        load_env(anchor_file=__file__)
        self.project_root = str(resolve_project_root(__file__))
        self.workflow = AnalysisWorkflow(self.project_root)

        self.current_log_path: str | None = None
        self.current_parse_result = None
        self.current_ai_result = None
        self.current_output_paths: dict[str, str] = {}

        self.mode_var = tk.StringVar(value="Normal Parse")
        self.api_key_var = tk.StringVar(value=os.environ.get("RFBOX_API_KEY", ""))
        self.file_var = tk.StringVar(value="No log file loaded")
        self.status_var = tk.StringVar(value="Load a UART log to begin.")
        self.cloud_var = tk.StringVar(value=f"Cloud AI: {self.workflow.llm.api_model}")
        self.summary_var = tk.StringVar(value="Waiting for input")

        self.metric_vars = {
            "severity": tk.StringVar(value="--"),
            "commands": tk.StringVar(value="0"),
            "anomalies": tk.StringVar(value="0"),
            "errors": tk.StringVar(value="0"),
        }

        self._build_ui()
        self._on_mode_change(self.mode_var.get())

    def _build_ui(self):
        outer = ctk.CTkFrame(self.root, corner_radius=0)
        outer.pack(fill="both", expand=True)

        hero = ctk.CTkFrame(outer, fg_color="#111827")
        hero.pack(fill="x", padx=14, pady=(14, 10))

        title = ctk.CTkLabel(hero, text="Radio Forensic Box", font=ctk.CTkFont(size=30, weight="bold"))
        title.pack(anchor="w", padx=18, pady=(16, 2))

        subtitle = ctk.CTkLabel(
            hero,
            text="Deterministic UART parsing first, cloud AI enrichment second.",
            text_color="#a5b4c3",
            font=ctk.CTkFont(size=14),
        )
        subtitle.pack(anchor="w", padx=18, pady=(0, 12))

        hero_footer = ctk.CTkFrame(hero, fg_color="transparent")
        hero_footer.pack(fill="x", padx=18, pady=(0, 16))

        status_label = ctk.CTkLabel(hero_footer, textvariable=self.status_var, text_color="#dbeafe")
        status_label.pack(side="left")

        cloud_label = ctk.CTkLabel(hero_footer, textvariable=self.cloud_var, text_color="#93c5fd")
        cloud_label.pack(side="right")

        controls = ctk.CTkFrame(outer)
        controls.pack(fill="x", padx=14, pady=(0, 10))

        left_controls = ctk.CTkFrame(controls, fg_color="transparent")
        left_controls.pack(side="left", fill="x", expand=True, padx=10, pady=10)

        self.load_btn = ctk.CTkButton(left_controls, text="Load Log File", command=self._on_load_file, width=140)
        self.load_btn.pack(side="left", padx=(0, 10))

        self.mode_button = ctk.CTkSegmentedButton(
            left_controls,
            values=["Normal Parse", "AI Enrich"],
            variable=self.mode_var,
            command=self._on_mode_change,
            width=220,
        )
        self.mode_button.pack(side="left", padx=(0, 10))

        self.run_btn = ctk.CTkButton(left_controls, text="Run Normal Parse", command=self._on_run_analysis, width=160)
        self.run_btn.pack(side="left", padx=(0, 10))

        self.outputs_btn = ctk.CTkButton(
            left_controls,
            text="Open Outputs Folder",
            command=self._on_open_outputs,
            width=160,
            state=tk.DISABLED,
        )
        self.outputs_btn.pack(side="left")

        right_controls = ctk.CTkFrame(controls, fg_color="transparent")
        right_controls.pack(side="right", padx=10, pady=10)

        api_label = ctk.CTkLabel(right_controls, text="Cloud API Key")
        api_label.pack(anchor="w")

        self.api_entry = ctk.CTkEntry(
            right_controls,
            width=340,
            show="*",
            placeholder_text="RFBOX_API_KEY",
            textvariable=self.api_key_var,
        )
        self.api_entry.pack(anchor="w", pady=(4, 0))

        file_bar = ctk.CTkFrame(outer)
        file_bar.pack(fill="x", padx=14, pady=(0, 10))

        file_caption = ctk.CTkLabel(file_bar, text="Active Case", text_color="#93c5fd")
        file_caption.pack(anchor="w", padx=12, pady=(10, 0))

        file_label = ctk.CTkLabel(file_bar, textvariable=self.file_var, anchor="w")
        file_label.pack(fill="x", padx=12, pady=(2, 10))

        progress_frame = ctk.CTkFrame(outer)
        progress_frame.pack(fill="x", padx=14, pady=(0, 10))

        self.progress_label = ctk.CTkLabel(progress_frame, textvariable=self.summary_var, anchor="w")
        self.progress_label.pack(fill="x", padx=12, pady=(10, 6))

        self.progress_bar = ctk.CTkProgressBar(progress_frame, mode="indeterminate")
        self.progress_bar.pack(fill="x", padx=12, pady=(0, 12))
        self.progress_bar.stop()
        self.progress_bar.set(0)

        metrics = ctk.CTkFrame(outer)
        metrics.pack(fill="x", padx=14, pady=(0, 10))

        self._build_metric_card(metrics, "Severity", self.metric_vars["severity"]).pack(side="left", fill="x", expand=True, padx=(10, 5), pady=10)
        self._build_metric_card(metrics, "Commands", self.metric_vars["commands"]).pack(side="left", fill="x", expand=True, padx=5, pady=10)
        self._build_metric_card(metrics, "Anomalies", self.metric_vars["anomalies"]).pack(side="left", fill="x", expand=True, padx=5, pady=10)
        self._build_metric_card(metrics, "Errors", self.metric_vars["errors"]).pack(side="left", fill="x", expand=True, padx=(5, 10), pady=10)

        body = ctk.CTkFrame(outer)
        body.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        sidebar = ctk.CTkFrame(body, width=340)
        sidebar.pack(side="left", fill="y", padx=(10, 8), pady=10)
        sidebar.pack_propagate(False)

        notes_label = ctk.CTkLabel(sidebar, text="Case Notes", anchor="w", font=ctk.CTkFont(size=18, weight="bold"))
        notes_label.pack(fill="x", padx=10, pady=(10, 4))

        self.notes_text = self._build_textbox(sidebar, height=14)
        self.notes_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        findings_label = ctk.CTkLabel(sidebar, text="Detected Anomalies", anchor="w", font=ctk.CTkFont(size=18, weight="bold"))
        findings_label.pack(fill="x", padx=10, pady=(0, 4))

        self.findings_text = self._build_textbox(sidebar, height=16)
        self.findings_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        content = ctk.CTkFrame(body)
        content.pack(side="left", fill="both", expand=True, padx=(0, 10), pady=10)

        self.tabs = ctk.CTkTabview(content)
        self.tabs.pack(fill="both", expand=True, padx=10, pady=10)
        for name in ("Overview", "Timeline", "Parser JSON", "AI Report", "AI JSON"):
            self.tabs.add(name)

        self.overview_text = self._build_textbox(self.tabs.tab("Overview"))
        self.overview_text.pack(fill="both", expand=True, padx=10, pady=10)

        self.timeline_text = scrolledtext.ScrolledText(
            self.tabs.tab("Timeline"),
            wrap=tk.NONE,
            bg="#0f172a",
            fg="#e2e8f0",
            insertbackground="#e2e8f0",
            relief=tk.FLAT,
        )
        self.timeline_text.pack(fill="both", expand=True, padx=10, pady=10)
        self._configure_timeline_tags()

        self.parser_json_text = self._build_textbox(self.tabs.tab("Parser JSON"))
        self.parser_json_text.pack(fill="both", expand=True, padx=10, pady=10)

        self.ai_report_text = self._build_textbox(self.tabs.tab("AI Report"))
        self.ai_report_text.pack(fill="both", expand=True, padx=10, pady=10)

        self.ai_json_text = self._build_textbox(self.tabs.tab("AI JSON"))
        self.ai_json_text.pack(fill="both", expand=True, padx=10, pady=10)

        self._clear_results()

    def _build_metric_card(self, parent, label: str, value_var: tk.StringVar):
        card = ctk.CTkFrame(parent)
        value = ctk.CTkLabel(card, textvariable=value_var, font=ctk.CTkFont(size=28, weight="bold"))
        value.pack(anchor="w", padx=14, pady=(12, 2))
        caption = ctk.CTkLabel(card, text=label, text_color="#94a3b8")
        caption.pack(anchor="w", padx=14, pady=(0, 12))
        return card

    def _build_textbox(self, parent, height: int | None = None):
        widget = scrolledtext.ScrolledText(
            parent,
            wrap=tk.WORD,
            height=height,
            bg="#0f172a",
            fg="#e2e8f0",
            insertbackground="#e2e8f0",
            relief=tk.FLAT,
        )
        return widget

    def _configure_timeline_tags(self):
        self.timeline_text.tag_config("normal", foreground="#dbeafe")
        self.timeline_text.tag_config("warning", foreground="#facc15")
        self.timeline_text.tag_config("error", foreground="#fb7185")
        self.timeline_text.tag_config("meta", foreground="#7dd3fc")

    def _set_text(self, widget, content: str):
        widget.config(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.insert(tk.END, content or "")
        widget.config(state=tk.DISABLED)

    def _set_status(self, text: str):
        self.status_var.set(text)
        self.summary_var.set(text)

    def _set_busy(self, busy: bool, message: str):
        self.load_btn.configure(state=tk.DISABLED if busy else tk.NORMAL)
        self.run_btn.configure(state=tk.DISABLED if busy else tk.NORMAL)
        self.outputs_btn.configure(state=tk.DISABLED if busy or not self.current_output_paths else tk.NORMAL)
        self.mode_button.configure(state=tk.DISABLED if busy else tk.NORMAL)
        self.api_entry.configure(state=tk.DISABLED if busy else tk.NORMAL)
        if busy:
            self.summary_var.set(message)
            self.progress_bar.start()
        else:
            self.summary_var.set(message)
            self.progress_bar.stop()
            self.progress_bar.set(0)

    def _clear_results(self):
        self._set_text(self.notes_text, "Load a log file and run a parse mode to populate case notes.")
        self._set_text(self.findings_text, "Detected anomalies will appear here.")
        self._set_text(self.overview_text, "Normal Parse output will appear here.")
        self._set_text(self.timeline_text, "")
        self._set_text(self.parser_json_text, "")
        self._set_text(self.ai_report_text, "AI Enrich results will appear here when enabled.")
        self._set_text(self.ai_json_text, "")
        self.metric_vars["severity"].set("--")
        self.metric_vars["commands"].set("0")
        self.metric_vars["anomalies"].set("0")
        self.metric_vars["errors"].set("0")

    def _on_mode_change(self, value: str):
        button_text = "Run AI Enrich" if value == "AI Enrich" else "Run Normal Parse"
        self.run_btn.configure(text=button_text)
        if value == "AI Enrich":
            self._set_status("AI Enrich mode will run Normal Parse first, then cloud AI.")
        else:
            self._set_status("Normal Parse mode runs deterministic Python analysis only.")

    def _on_load_file(self):
        path = filedialog.askopenfilename(
            title="Select UART AT log file",
            filetypes=[("Text files", "*.txt;*.log"), ("All files", "*")],
        )
        if not path:
            return

        self.current_log_path = path
        self.current_parse_result = None
        self.current_ai_result = None
        self.current_output_paths = {}
        self.outputs_btn.configure(state=tk.DISABLED)
        self._clear_results()

        try:
            line_count = sum(1 for _ in Path(path).open("r", encoding="utf-8", errors="ignore"))
        except Exception:
            line_count = 0

        self.file_var.set(f"{path}  |  {line_count} lines")
        self.summary_var.set("File loaded. Choose a mode and run analysis.")

    def _on_run_analysis(self):
        if not self.current_log_path:
            self._set_status("Load a log file before running analysis.")
            return

        mode = self.mode_var.get()
        api_key = self.api_key_var.get().strip()
        if mode == "AI Enrich" and not (api_key or self.workflow.llm.api_key):
            self._set_status("AI Enrich requires RFBOX_API_KEY.")
            return

        self._set_busy(True, "Running deterministic parse...")

        def _worker():
            try:
                parse_bundle = self.workflow.parse_log(self.current_log_path)
                report = parse_bundle["report"]
                overview_markdown = parse_bundle["overview_markdown"]

                ai_result = None
                key_to_use = api_key or self.workflow.llm.api_key
                if mode == "AI Enrich":
                    self.workflow.llm.update_config(api_key=key_to_use)
                    self.root.after(0, lambda: self._set_status("Deterministic parse complete. Calling cloud AI..."))
                    ai_result = self.workflow.enrich_with_ai(report)

                paths = self.workflow.save_outputs(self.current_log_path, report, overview_markdown, ai_result)
                self.root.after(0, lambda: self._apply_results(report, overview_markdown, ai_result, paths, mode))
            except Exception as exc:
                self.root.after(0, lambda: self._handle_error(str(exc)))

        threading.Thread(target=_worker, daemon=True).start()

    def _apply_results(self, report, overview_markdown: str, ai_result, paths: dict[str, str], mode: str):
        self.current_parse_result = report
        self.current_ai_result = ai_result
        self.current_output_paths = paths
        self.outputs_btn.configure(state=tk.NORMAL)

        stats = report.get("stats", {})
        self.metric_vars["severity"].set(report.get("severity", "unknown").upper())
        self.metric_vars["commands"].set(str(stats.get("commands", 0)))
        self.metric_vars["anomalies"].set(str(len(report.get("anomalies", []))))
        self.metric_vars["errors"].set(str(stats.get("errors", 0)))

        note_lines = [
            f"Mode: {mode}",
            f"Source: {Path(self.current_log_path).name if self.current_log_path else 'n/a'}",
            f"Severity: {report.get('severity', 'unknown').upper()}",
            "",
            "Outputs:",
        ]
        for key, value in paths.items():
            note_lines.append(f"- {key}: {Path(value).name}")
        self._set_text(self.notes_text, "\n".join(note_lines))

        self._set_text(self.findings_text, build_anomaly_panel_text(report))
        self._set_text(self.overview_text, overview_markdown)
        self._set_text(self.parser_json_text, json.dumps(report, indent=2, ensure_ascii=False))

        self.timeline_text.config(state=tk.NORMAL)
        self.timeline_text.delete("1.0", tk.END)
        for row, style in build_timeline_rows(report):
            self.timeline_text.insert(tk.END, row + "\n", style)
        self.timeline_text.config(state=tk.DISABLED)

        if ai_result:
            self._set_text(self.ai_report_text, build_ai_markdown(ai_result))
            self._set_text(self.ai_json_text, json.dumps(ai_result.get("parsed"), indent=2, ensure_ascii=False))
        else:
            self._set_text(self.ai_report_text, "AI Enrich was not run for this case.")
            self._set_text(self.ai_json_text, "")

        self._set_busy(False, f"{mode} complete. Outputs saved to outputs/.")

    def _handle_error(self, message: str):
        self._set_busy(False, f"Analysis failed: {message}")

    def _on_open_outputs(self):
        outputs_dir = str(self.workflow.outputs_dir)
        try:
            if hasattr(os, "startfile"):
                os.startfile(outputs_dir)
            else:
                self._set_status(outputs_dir)
        except Exception as exc:
            self._set_status(f"Could not open outputs folder: {exc}")

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = RadioForensicApp()
    app.run()
