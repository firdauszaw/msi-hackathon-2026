#!/usr/bin/env python3
"""Compact deterministic summary parser.

Usage: python scripts/quick_parse_summary.py "logs/TEST ATCMD.txt"
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from radio_forensic_box.parser import LogParser


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "logs/TEST ATCMD.txt"
    p = LogParser(path)
    report = p.parse_report()
    stats = report["stats"]

    print(report["summary"])
    print("Severity:", report["severity"])
    print("Commands:", stats["commands"])
    print("Responses:", stats["responses"])
    print("Errors:", stats["errors"])
    print("Anomalies:", len(report["anomalies"]))

    if report["anomalies"]:
        print("\nTop anomalies:")
        for anomaly in report["anomalies"][:5]:
            print(f"- {anomaly['id']} {anomaly['title']} (line {anomaly['start_line']})")


if __name__ == '__main__':
    main()
