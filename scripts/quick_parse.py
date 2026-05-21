#!/usr/bin/env python3
"""Quick deterministic parse runner.

Usage: python scripts/quick_parse.py "logs/TEST ATCMD.txt"
"""

import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from radio_forensic_box.parser import LogParser
from radio_forensic_box.reporting import build_normal_parse_markdown


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "logs/TEST ATCMD.txt"
    parser = LogParser(path)
    report = parser.parse_report()

    print(build_normal_parse_markdown(report))
    print("\n--- JSON preview ---\n")
    print(json.dumps(report, indent=2, ensure_ascii=False)[:4000])


if __name__ == '__main__':
    main()
