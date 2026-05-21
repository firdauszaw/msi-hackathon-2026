# Radio Forensic Box

Radio Forensic Box is a Windows desktop app for analyzing UART and AT-command logs from a TETRA radio workflow.

The app now uses a two-stage pipeline:

1. Normal Parse
    Deterministic Python parsing that builds a structured forensic report with events, command-response sessions, anomalies, severity, and recommendations.
2. AI Enrich
    Optional cloud AI review that reads the deterministic parse report and adds likely root causes, operator actions, and a concise forensic narrative.

This keeps the parser reliable and makes the AI step additive instead of replacing the parser.

## Current Workflow

- Load a log file.
- Choose `Normal Parse` or `AI Enrich`.
- Run the analysis.
- Review the output in the desktop UI tabs:
   - Overview
   - Timeline
   - Parser JSON
   - AI Report
   - AI JSON

Generated output files are written to `outputs/` using the loaded file name as the prefix.

## Quick Start

### 1. Create a virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

### 2. Configure cloud AI

Create a `.env` file in the project root with:

```env
RFBOX_API_KEY=your-api-key
RFBOX_API_MODEL=VertexGemini
RFBOX_API_BASE=https://genai-service.stage.commandcentral.com/app-gateway/api/v2/chat
```

Only `RFBOX_API_KEY` is required if you want to use the default endpoint and model.

### 3. Run the desktop app

```powershell
.\.venv\Scripts\python.exe main.py
```

## Dependencies

- `customtkinter` for the desktop UI
- `requests` for the cloud AI call
- `python-docx` optionally, to extract command descriptions from the reference DOCX if it is present in the project root

## Optional Reference Document

If `1135099- MR2026.1_AT_Programmers_Guide_v1.docx` exists in the project root, the app will try to extract command descriptions and enrich deterministic parsing with those mappings.

## Helper Scripts

- `scripts/quick_parse.py`
   Runs the deterministic parser and prints a human-readable summary plus JSON preview.
- `scripts/quick_parse_summary.py`
   Prints a short parser summary for a sample log.
- `run_llm_analyze.py`
   Runs the full deterministic parse plus cloud AI enrichment flow on the sample log.

## Output Files

For a log file named `TEST ATCMD.txt`, the app writes files like:

- `outputs/TEST_ATCMD.normal.json`
- `outputs/TEST_ATCMD.normal.md`
- `outputs/TEST_ATCMD.ai.json`
- `outputs/TEST_ATCMD.ai.md`
- `outputs/TEST_ATCMD.ai.raw.txt`

## Notes

- The app is now cloud-only for AI features. Local GGUF and `llama-cpp-python` paths were removed.
- `Normal Parse` does not require an API key.
- `AI Enrich` always runs `Normal Parse` first and then sends the structured parse report to cloud AI.
- Generated outputs and virtual environments are ignored by git.

