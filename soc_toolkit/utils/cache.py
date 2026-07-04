"""
A tiny, dependency-free disk cache used to avoid hammering rate-limited
threat-intel APIs when the same indicator is looked up repeatedly.

Each cache entry is a JSON file named after a hash of (source, key).
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Optional

from soc_toolkit.config import CACHE_DIR, settings


def _cache_path(source: str, key: str) -> Path:
    digest = hashlib.sha256(f"{source}:{key}".encode()).hexdigest()
    return CACHE_DIR / f"{digest}.json"


def get(source: str, key: str) -> Optional[Any]:
    path = _cache_path(source, key)
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None

    if time.time() - payload.get("_cached_at", 0) > settings.cache_ttl:
        return None  # expired

    return payload.get("data")


def set(source: str, key: str, data: Any) -> None:
    path = _cache_path(source, key)
    payload = {"_cached_at": time.time(), "source": source, "key": key, "data": data}
    try:
        path.write_text(json.dumps(payload, default=str))
    except OSError:
        pass  # caching is best-effort; never fail the caller because of it


def clear() -> int:
    count = 0
    for f in CACHE_DIR.glob("*.json"):
        f.unlink(missing_ok=True)
        count += 1
    return count
