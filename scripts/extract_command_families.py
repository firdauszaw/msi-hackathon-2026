#!/usr/bin/env python3
"""Generate an XML catalog of AT command families from the programmer guide."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from radio_forensic_box.docparser import write_command_families_xml


def main() -> int:
    docx_path = sys.argv[1] if len(sys.argv) > 1 else "1135099- MR2026.1_AT_Programmers_Guide_v1.docx"
    output_path = sys.argv[2] if len(sys.argv) > 2 else "radio_forensic_box/tetra_at_command_families.xml"

    families = write_command_families_xml(docx_path, output_path)
    command_count = sum(len(family["commands"]) for family in families)
    print(f"Wrote {len(families)} families and {command_count} command headings to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())