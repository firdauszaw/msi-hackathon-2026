import pathlib

from radio_forensic_box.env import load_env
from radio_forensic_box.workflow import AnalysisWorkflow


def main():
    load_env(path=str(pathlib.Path(__file__).parent / ".env"))
    logs_path = pathlib.Path(__file__).parent / "logs" / "TEST ATCMD.txt"
    if not logs_path.exists():
        print("No test log found:", logs_path)
        raise SystemExit(1)

    workflow = AnalysisWorkflow(str(pathlib.Path(__file__).parent))
    parse_bundle = workflow.parse_log(str(logs_path))
    report = parse_bundle["report"]
    overview_markdown = parse_bundle["overview_markdown"]

    print("Starting cloud AI enrichment from deterministic parse report...")
    try:
        res = workflow.enrich_with_ai(report)
    except Exception as e:
        print("Analysis failed:", e)
        raise

    paths = workflow.save_outputs(str(logs_path), report, overview_markdown, res)

    print("Saved outputs:")
    for key, value in paths.items():
        print(f"- {key}: {value}")

    parsed = res.get("parsed")
    if isinstance(parsed, dict):
        if parsed.get("_parse_error"):
            print("Parse error:", parsed.get("_parse_error"))
        else:
            print("AI executive summary:", parsed.get("executive_summary"))
    else:
        print("No parsed JSON returned.")

    print("Done")


if __name__ == "__main__":
    main()
