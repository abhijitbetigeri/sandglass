"""Credential loading for Sandglass.

Reads .env.local from the repo root, without overriding anything already set
in the real environment (so CI and `export` still win).
"""
from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = REPO_ROOT / ".env.local"


def load_env(path: Path | None = None) -> dict[str, str]:
    """Minimal .env parser — no dependency, no surprises."""
    target = Path(path) if path else ENV_FILE
    loaded: dict[str, str] = {}
    if not target.exists():
        return loaded
    for raw in target.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip().strip('"').strip("'")
        if not val:
            continue
        loaded[key] = val
        os.environ.setdefault(key, val)
    return loaded


def require(*names: str) -> None:
    """Fail early and say exactly which key is missing and where to put it."""
    load_env()
    missing = [n for n in names if not os.environ.get(n)]
    if missing:
        raise SystemExit(
            "missing credential(s): " + ", ".join(missing)
            + f"\nadd them to {ENV_FILE}"
        )


def tenki_token() -> str | None:
    load_env()
    return os.environ.get("TENKI_AUTH_TOKEN") or os.environ.get("TENKI_API_KEY")
