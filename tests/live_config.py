"""Settings for the live device tests (``-m online`` and ``PYLOXONE_LIVE=1``).

Values come from the environment first. Missing ones are read from
``.env.live`` in the project root, which is git-ignored. The file must be
readable only by its owner (mode 0600). Values are never printed.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

ENV_FILE = Path(__file__).resolve().parent.parent / ".env.live"
KEYS = ("PYLOXONE_TEST_HOST", "PYLOXONE_TEST_USER", "PYLOXONE_TEST_PASSWORD")
DEFAULT_PORT = 8080


def _read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def load_live_settings() -> tuple[dict[str, str] | None, str]:
    """Return ``(settings, "")`` if complete, else ``(None, reason)``."""
    values = {key: os.environ.get(key, "") for key in KEYS}
    if not all(values.values()) and ENV_FILE.is_file():
        mode = stat.S_IMODE(ENV_FILE.stat().st_mode)
        if mode & 0o077:
            return None, f"{ENV_FILE.name} must have mode 0600 (chmod 600 .env.live)"
        for key, value in _read_env(ENV_FILE).items():
            if key in values and not values[key]:
                values[key] = value
    missing = [key for key, value in values.items() if not value]
    if missing:
        return None, (
            "missing " + ", ".join(missing)
            + " (set them in the environment or in .env.live)"
        )
    return values, ""


def host_and_port(value: str) -> tuple[str, int]:
    if ":" in value:
        host, _, port = value.rpartition(":")
        if port.isdigit():
            return host, int(port)
    return value, DEFAULT_PORT
