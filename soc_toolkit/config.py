"""
Central configuration for SOC Toolkit.

Loads settings from a `.env` file (see `.env.example`) so that no secrets
are ever hard-coded. Every consumer of an API key should go through this
module and must tolerate a missing key by skipping that data source rather
than crashing.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

# Load .env from project root if present
PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

CACHE_DIR = PROJECT_ROOT / ".cache"
CACHE_DIR.mkdir(exist_ok=True)

REPORTS_DIR = PROJECT_ROOT / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

RULES_DIR = Path(__file__).resolve().parent / "rules"


@dataclass
class Settings:
    vt_api_key: str = os.getenv("VT_API_KEY", "")
    abuseipdb_api_key: str = os.getenv("ABUSEIPDB_API_KEY", "")
    shodan_api_key: str = os.getenv("SHODAN_API_KEY", "")
    gsb_api_key: str = os.getenv("GSB_API_KEY", "")
    cache_ttl: int = int(os.getenv("CACHE_TTL", "21600"))
    request_timeout: int = int(os.getenv("REQUEST_TIMEOUT", "15"))

    def enabled_sources(self) -> list[str]:
        sources = []
        if self.vt_api_key:
            sources.append("virustotal")
        if self.abuseipdb_api_key:
            sources.append("abuseipdb")
        if self.shodan_api_key:
            sources.append("shodan")
        if self.gsb_api_key:
            sources.append("google_safe_browsing")
        return sources


settings = Settings()
