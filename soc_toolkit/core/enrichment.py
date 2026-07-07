"""
IOC Enrichment Engine
======================
Queries multiple threat-intelligence sources for a single indicator
(IP, domain, URL, or file hash) and aggregates the results into one
normalized verdict, similar in spirit to Cortex/IntelOwl analyzers.

Design goals:
  - Never crash on a missing API key -> just skip that source.
  - Never crash on a network error / rate limit -> record the error and move on.
  - Cache every successful lookup to respect free-tier rate limits.
"""
from __future__ import annotations

import base64
from typing import Any, Dict

import requests

from soc_toolkit.config import settings
from soc_toolkit.utils import cache
from soc_toolkit.utils.logger import get_logger
from soc_toolkit.utils.validators import IOCType, detect_ioc_type

log = get_logger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"
SHODAN_BASE = "https://api.shodan.io"


def _get(url: str, **kwargs) -> requests.Response:
    kwargs.setdefault("timeout", settings.request_timeout)
    return requests.get(url, **kwargs)


# ---------------------------------------------------------------------------
# Individual source checks
# ---------------------------------------------------------------------------

def check_virustotal(ioc: str, ioc_type: str) -> Dict[str, Any]:
    if not settings.vt_api_key:
        return {"source": "virustotal", "status": "skipped", "reason": "no API key"}

    cached = cache.get("virustotal", ioc)
    if cached:
        return cached

    headers = {"x-apikey": settings.vt_api_key}
    try:
        if ioc_type in (IOCType.IPV4, IOCType.IPV6):
            url = f"{VT_BASE}/ip_addresses/{ioc}"
        elif ioc_type == IOCType.DOMAIN:
            url = f"{VT_BASE}/domains/{ioc}"
        elif ioc_type == IOCType.URL:
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            url = f"{VT_BASE}/urls/{url_id}"
        elif ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
            url = f"{VT_BASE}/files/{ioc}"
        else:
            return {"source": "virustotal", "status": "unsupported_type"}

        resp = _get(url, headers=headers)
        if resp.status_code == 404:
            result = {"source": "virustotal", "status": "not_found"}
        elif resp.status_code == 401:
            result = {"source": "virustotal", "status": "error", "reason": "invalid API key"}
        elif resp.status_code == 429:
            result = {"source": "virustotal", "status": "rate_limited"}
        elif resp.ok:
            stats = (
                resp.json()
                .get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )
            result = {
                "source": "virustotal",
                "status": "ok",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "link": f"https://www.virustotal.com/gui/search/{ioc}",
            }
        else:
            result = {"source": "virustotal", "status": "error", "reason": f"HTTP {resp.status_code}"}
    except requests.RequestException as exc:
        result = {"source": "virustotal", "status": "error", "reason": str(exc)}

    if result.get("status") == "ok":
        cache.set("virustotal", ioc, result)
    return result


def check_abuseipdb(ip: str) -> Dict[str, Any]:
    if not settings.abuseipdb_api_key:
        return {"source": "abuseipdb", "status": "skipped", "reason": "no API key"}

    cached = cache.get("abuseipdb", ip)
    if cached:
        return cached

    headers = {"Key": settings.abuseipdb_api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        resp = _get(f"{ABUSEIPDB_BASE}/check", headers=headers, params=params)
        if resp.status_code == 401:
            result = {"source": "abuseipdb", "status": "error", "reason": "invalid API key"}
        elif resp.status_code == 429:
            result = {"source": "abuseipdb", "status": "rate_limited"}
        elif resp.ok:
            data = resp.json().get("data", {})
            result = {
                "source": "abuseipdb",
                "status": "ok",
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country_code": data.get("countryCode"),
                "isp": data.get("isp"),
                "link": f"https://www.abuseipdb.com/check/{ip}",
            }
        else:
            result = {"source": "abuseipdb", "status": "error", "reason": f"HTTP {resp.status_code}"}
    except requests.RequestException as exc:
        result = {"source": "abuseipdb", "status": "error", "reason": str(exc)}

    if result.get("status") == "ok":
        cache.set("abuseipdb", ip, result)
    return result


def check_shodan(ip: str) -> Dict[str, Any]:
    if not settings.shodan_api_key:
        return {"source": "shodan", "status": "skipped", "reason": "no API key"}

    cached = cache.get("shodan", ip)
    if cached:
        return cached

    try:
        resp = _get(f"{SHODAN_BASE}/shodan/host/{ip}", params={"key": settings.shodan_api_key})
        if resp.status_code == 404:
            result = {"source": "shodan", "status": "not_found"}
        elif resp.status_code == 401:
            result = {"source": "shodan", "status": "error", "reason": "invalid API key"}
        elif resp.ok:
            data = resp.json()
            result = {
                "source": "shodan",
                "status": "ok",
                "open_ports": data.get("ports", []),
                "org": data.get("org"),
                "os": data.get("os"),
                "hostnames": data.get("hostnames", []),
                "link": f"https://www.shodan.io/host/{ip}",
            }
        else:
            result = {"source": "shodan", "status": "error", "reason": f"HTTP {resp.status_code}"}
    except requests.RequestException as exc:
        result = {"source": "shodan", "status": "error", "reason": str(exc)}

    if result.get("status") == "ok":
        cache.set("shodan", ip, result)
    return result


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def _compute_verdict(sources: list[Dict[str, Any]]) -> Dict[str, Any]:
    """Roll up individual source results into a single risk verdict."""
    score = 0
    reasons = []

    for s in sources:
        if s.get("status") != "ok":
            continue
        if s["source"] == "virustotal" and s.get("malicious", 0) > 0:
            score += min(s["malicious"] * 15, 80)
            reasons.append(f"VirusTotal: {s['malicious']} engines flagged malicious")
        if s["source"] == "abuseipdb" and s.get("abuse_confidence_score", 0) >= 25:
            score += s["abuse_confidence_score"] // 2
            reasons.append(f"AbuseIPDB confidence score {s['abuse_confidence_score']}%")

    score = min(score, 100)
    if score >= 70:
        verdict = "malicious"
    elif score >= 30:
        verdict = "suspicious"
    elif any(s.get("status") == "ok" for s in sources):
        verdict = "clean"
    else:
        verdict = "unknown"

    return {"risk_score": score, "verdict": verdict, "reasons": reasons}


def enrich_ioc(ioc: str) -> Dict[str, Any]:
    """Main entrypoint: classify + query all applicable sources for one IOC."""
    ioc = ioc.strip()
    ioc_type = detect_ioc_type(ioc)
    log.info(f"Enriching [bold]{ioc}[/bold] (type: {ioc_type})")

    sources = []

    if ioc_type == IOCType.UNKNOWN:
        return {
            "ioc": ioc,
            "type": ioc_type,
            "sources": [],
            "risk_score": 0,
            "verdict": "unrecognized",
            "reasons": ["Could not classify indicator type"],
        }

    # VirusTotal supports every type
    sources.append(check_virustotal(ioc, ioc_type))

    # IP-only sources
    if ioc_type in (IOCType.IPV4, IOCType.IPV6):
        sources.append(check_abuseipdb(ioc))
        sources.append(check_shodan(ioc))

    # If no providers were actually enabled, the individual check_* helpers
    # will return 'skipped' entries. However the user requested an early
    # return when there are no enabled providers: return an explicit unknown
    # verdict with empty sources to avoid even calling check_* helpers.
    if not settings.enabled_sources():
        log.warning("No threat-intel providers configured; returning unknown for %s", ioc)
        return {
            "ioc": ioc,
            "type": ioc_type,
            "sources": [],
            "risk_score": 0,
            "verdict": "unknown",
        }

    verdict = _compute_verdict(sources)

    return {
        "ioc": ioc,
        "type": ioc_type,
        "sources": sources,
        **verdict,
    }


def enrich_bulk(iocs: list[str]) -> list[Dict[str, Any]]:
    """Enrich a batch of IOCs (e.g. from a SIEM alert or phishing email)."""
    return [enrich_ioc(ioc) for ioc in dict.fromkeys(iocs)]  # de-dupe, preserve order
