"""Environment helpers for Radio Forensic Box."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


def resolve_project_root(anchor_file: str) -> Path:
    return Path(anchor_file).resolve().parent.parent


def load_env(path: Optional[str] = None, anchor_file: Optional[str] = None) -> Optional[Path]:
    if path:
        env_path = Path(path)
    elif anchor_file:
        env_path = resolve_project_root(anchor_file) / ".env"
    else:
        env_path = Path.cwd() / ".env"

    if not env_path.exists():
        return None

    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value

    return env_path