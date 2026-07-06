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

# ------------------------------------------------------------
# Project paths
# ------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

load_dotenv(PROJECT_ROOT / ".env")

CACHE_DIR = PROJECT_ROOT / ".cache"
CACHE_DIR.mkdir(exist_ok=True)

REPORTS_DIR = PROJECT_ROOT / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

RULES_DIR = Path(__file__).resolve().parent / "rules"

# ------------------------------------------------------------
# Settings
# ------------------------------------------------------------

@dataclass
class Settings:
    # ==========================================================
    # Threat Intelligence Providers
    # ==========================================================

    vt_api_key: str = os.getenv("VT_API_KEY", "")
    abuseipdb_api_key: str = os.getenv("ABUSEIPDB_API_KEY", "")
    shodan_api_key: str = os.getenv("SHODAN_API_KEY", "")

    xforce_api_key: str = os.getenv("XFORCE_API_KEY", "")
    xforce_api_password: str = os.getenv("XFORCE_API_PASSWORD", "")

    otx_api_key: str = os.getenv("OTX_API_KEY", "")

    pulsedive_api_key: str = os.getenv("PULSEDIVE_API_KEY", "")

    censys_api_id: str = os.getenv("CENSYS_API_ID", "")
    censys_api_secret: str = os.getenv("CENSYS_API_SECRET", "")

    zoomeye_api_key: str = os.getenv("ZOOMEYE_API_KEY", "")

    talos_api_key: str = os.getenv("TALOS_API_KEY", "")

    phishtank_api_key: str = os.getenv("PHISHTANK_API_KEY", "")

    gsb_api_key: str = os.getenv("GSB_API_KEY", "")

    urlscan_api_key: str = os.getenv("URLSCAN_API_KEY", "")

    urlhaus_api_key: str = os.getenv("URLHAUS_API_KEY", "")

    hybrid_analysis_api_key: str = os.getenv("HYBRID_ANALYSIS_API_KEY", "")

    greynoise_api_key: str = os.getenv("GREYNOISE_API_KEY", "")

    misp_url: str = os.getenv("MISP_URL", "")
    misp_api_key: str = os.getenv("MISP_API_KEY", "")

    opencti_url: str = os.getenv("OPENCTI_URL", "")
    opencti_token: str = os.getenv("OPENCTI_TOKEN", "")

    # ==========================================================
    # General Configuration
    # ==========================================================

    cache_ttl: int = int(os.getenv("CACHE_TTL", "21600"))
    request_timeout: int = int(os.getenv("REQUEST_TIMEOUT", "20"))
    max_parallel_requests: int = int(os.getenv("MAX_PARALLEL_REQUESTS", "10"))
    verify_ssl: bool = os.getenv("VERIFY_SSL", "True").lower() == "true"
    log_level: str = os.getenv("LOG_LEVEL", "INFO")

    def enabled_sources(self) -> list[str]:
        """Return a list of enabled providers."""

        providers = {
            "VirusTotal": self.vt_api_key,
            "AbuseIPDB": self.abuseipdb_api_key,
            "Shodan": self.shodan_api_key,
            "IBM X-Force": self.xforce_api_key,
            "AlienVault OTX": self.otx_api_key,
            "Pulsedive": self.pulsedive_api_key,
            "Censys": self.censys_api_id,
            "ZoomEye": self.zoomeye_api_key,
            "Cisco Talos": self.talos_api_key,
            "PhishTank": self.phishtank_api_key,
            "Google Safe Browsing": self.gsb_api_key,
            "URLScan": self.urlscan_api_key,
            "URLHaus": self.urlhaus_api_key,
            "Hybrid Analysis": self.hybrid_analysis_api_key,
            "GreyNoise": self.greynoise_api_key,
            "MISP": self.misp_api_key,
            "OpenCTI": self.opencti_token,
        }

        return [name for name, key in providers.items() if key]

settings = Settings()
