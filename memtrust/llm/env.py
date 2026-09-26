"""Tiny ``.env`` loader (stdlib only) so API keys stay out of code.

Supports ``KEY=value``, ``export KEY=value``, quotes, blank lines, and
``#`` comments. Existing environment variables win unless ``override``.
"""

from __future__ import annotations

import os
from pathlib import Path


def load_dotenv(path: str | os.PathLike[str] = ".env", *, override: bool = False) -> dict[str, str]:
    """Load variables from ``path`` into ``os.environ``; return what was read.

    A missing file is not an error (returns ``{}``).
    """
    file = Path(path)
    if not file.is_file():
        return {}
    values: dict[str, str] = {}
    for raw in file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        key, sep, value = line.partition("=")
        key = key.strip()
        if not sep or not key:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        values[key] = value
        if override or key not in os.environ:
            os.environ[key] = value
    return values


__all__ = ["load_dotenv"]
