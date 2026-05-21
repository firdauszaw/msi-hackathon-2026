"""Entry point for Radio Forensic Box."""

from pathlib import Path

from radio_forensic_box.env import load_env
from radio_forensic_box.ui import RadioForensicApp


def main():
    load_env(path=str(Path(__file__).parent / ".env"))

    app = RadioForensicApp()
    app.run()


if __name__ == "__main__":
    main()
