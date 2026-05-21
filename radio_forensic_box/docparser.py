"""
Simple DOCX-based command mapping extractor.

This module optionally reads a Word `.docx` reference and extracts nearby
descriptions for TETRA AT commands like `+CTSDC`, `+CTSP`, etc. It's best-effort
and safe-fails to an empty mapping if `python-docx` is not installed.
"""

from typing import Dict
import os
import re


def extract_mapping_from_docx(path: str) -> Dict[str, str]:
    """Extract a simple mapping of command -> short description from a .docx file.

    Returns an empty dict on failure.
    """
    try:
        from docx import Document
    except Exception as e:
        raise RuntimeError("python-docx is required to parse docx files: " + str(e))

    if not os.path.exists(path):
        raise FileNotFoundError(path)

    doc = Document(path)
    texts = []
    for p in doc.paragraphs:
        t = p.text.strip()
        if t:
            texts.append(t)

    # include table text as well
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                t = cell.text.strip()
                if t:
                    texts.append(t)

    mapping: Dict[str, str] = {}
    combined = "\n".join(texts)

    # Find +COMMAND tokens (letters/numbers, 3-12 chars)
    tokens = set(re.findall(r"\+([A-Z0-9]{3,12})\b", combined, flags=re.I))
    for token in tokens:
        # Find a paragraph containing the token
        pat = re.compile(rf"\+{re.escape(token)}\b", flags=re.I)
        desc = None
        for i, p in enumerate(texts):
            if pat.search(p):
                # remove the token from the paragraph and crop
                desc_candidate = pat.sub("", p).strip(" :-.\n")
                if desc_candidate:
                    desc = desc_candidate
                else:
                    # try the next paragraph as a short description
                    if i + 1 < len(texts):
                        desc = texts[i + 1].strip()
                break
        if desc:
            # Normalize whitespace and limit length
            desc = re.sub(r"\s+", " ", desc)
            if len(desc) > 200:
                desc = desc[:197] + "..."
            mapping[token.upper()] = desc

    return mapping


def safe_load_docx_mapping(path: str) -> Dict[str, str]:
    try:
        return extract_mapping_from_docx(path)
    except Exception:
        return {}


if __name__ == "__main__":
    print("docparser: use safe_load_docx_mapping(path) to extract mappings.")
