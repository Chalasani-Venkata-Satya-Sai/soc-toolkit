"""
Phishing Triage Engine
======================
Parses a raw .eml file, extracts headers, IOCs (URLs/IPs/domains), and
attachment hashes, then applies header-spoofing heuristics to produce a
quick triage verdict — the same first-pass work a Tier-1 analyst does
manually with a phishing mailbox submission.
"""
from __future__ import annotations

import hashlib
import re
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any, Dict, List

import tldextract

from soc_toolkit.utils.logger import get_logger
from soc_toolkit.utils.validators import detect_ioc_type

log = get_logger(__name__)

_URL_RE = re.compile(r"https?://[^\s\"'<>\)\]]+", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Freemail providers whose domain legitimately differs from a company display name
_FREEMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "icloud.com",
}

_URGENCY_KEYWORDS = [
    "urgent", "immediately", "verify your account", "suspended", "act now",
    "password expires", "click here", "confirm your identity", "unusual activity",
    "limited time", "wire transfer", "gift card",
]


def _extract_domain(addr: str) -> str | None:
    if "@" not in addr:
        return None
    return addr.rsplit("@", 1)[-1].strip(">").lower()


def _root_domain(domain: str) -> str:
    ext = tldextract.extract(domain)
    return ".".join(part for part in [ext.domain, ext.suffix] if part)


def parse_eml(file_path: str | Path) -> Dict[str, Any]:
    """Parse a raw .eml file and return structured header/body/IOC data."""
    file_path = Path(file_path)
    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    headers = {
        "from": msg.get("From", ""),
        "reply_to": msg.get("Reply-To", ""),
        "return_path": msg.get("Return-Path", ""),
        "subject": msg.get("Subject", ""),
        "to": msg.get("To", ""),
        "date": msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""),
    }
    received_chain = msg.get_all("Received", [])
    headers["received_hops"] = len(received_chain)
    headers["received_chain"] = [str(r) for r in received_chain]

    # Body text (plain preferred, fallback to stripped HTML)
    body_text = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body_text += part.get_content()
    else:
        body_text = msg.get_content() if not msg.get_filename() else ""

    # Attachments -> hashes
    attachments = []
    for part in msg.iter_attachments():
        payload = part.get_payload(decode=True) or b""
        attachments.append({
            "filename": part.get_filename() or "unnamed",
            "content_type": part.get_content_type(),
            "size_bytes": len(payload),
            "md5": hashlib.md5(payload).hexdigest() if payload else None,
            "sha256": hashlib.sha256(payload).hexdigest() if payload else None,
        })

    urls = sorted(set(_URL_RE.findall(body_text)))
    ips = sorted(set(_IP_RE.findall(body_text)))
    domains = sorted({
        _root_domain(u.split("/")[2]) for u in urls if len(u.split("/")) > 2
    })

    return {
        "file": str(file_path.name),
        "headers": headers,
        "body_preview": body_text[:500],
        "urls": urls,
        "ips": ips,
        "domains": domains,
        "attachments": attachments,
    }


def _score_headers(headers: Dict[str, Any]) -> tuple[int, List[str]]:
    score = 0
    reasons = []

    from_domain = _extract_domain(headers.get("from", ""))
    return_path_domain = _extract_domain(headers.get("return_path", ""))
    reply_to_domain = _extract_domain(headers.get("reply_to", ""))

    if from_domain and return_path_domain and from_domain != return_path_domain:
        if _root_domain(from_domain) != _root_domain(return_path_domain):
            score += 25
            reasons.append(
                f"From domain ({from_domain}) does not match Return-Path domain "
                f"({return_path_domain}) — classic spoofing indicator"
            )

    if reply_to_domain and from_domain and _root_domain(reply_to_domain) != _root_domain(from_domain):
        score += 20
        reasons.append(
            f"Reply-To domain ({reply_to_domain}) differs from From domain ({from_domain})"
        )

    if headers.get("received_hops", 0) == 0:
        score += 10
        reasons.append("No Received headers found — possibly a locally crafted/spoofed message")

    return score, reasons


def _score_content(body_text: str, urls: List[str], attachments: List[Dict]) -> tuple[int, List[str]]:
    score = 0
    reasons = []
    lowered = body_text.lower()

    hits = [kw for kw in _URGENCY_KEYWORDS if kw in lowered]
    if hits:
        score += min(len(hits) * 8, 30)
        reasons.append(f"Urgency/social-engineering language detected: {', '.join(hits[:5])}")

    for url in urls:
        domain = _root_domain(url.split("/")[2]) if len(url.split("/")) > 2 else ""
        if detect_ioc_type(url) == "url" and any(c.isdigit() for c in domain.split(".")[0] if domain):
            score += 5
            reasons.append(f"Suspicious raw-IP or numeric-looking link: {url}")

    risky_ext = (".exe", ".scr", ".js", ".vbs", ".bat", ".ps1", ".jar", ".hta")
    for att in attachments:
        if att["filename"].lower().endswith(risky_ext):
            score += 25
            reasons.append(f"Executable-type attachment: {att['filename']}")
        elif att["filename"].lower().endswith((".zip", ".rar", ".7z", ".iso")):
            score += 10
            reasons.append(f"Archive attachment (common malware delivery): {att['filename']}")

    return min(score, 100), reasons


def triage_email(file_path: str | Path) -> Dict[str, Any]:
    """Full pipeline: parse -> score -> verdict, ready for the CLI/dashboard."""
    parsed = parse_eml(file_path)
    header_score, header_reasons = _score_headers(parsed["headers"])
    content_score, content_reasons = _score_content(
        parsed["body_preview"], parsed["urls"], parsed["attachments"]
    )

    total_score = min(header_score + content_score, 100)
    if total_score >= 60:
        verdict = "phishing"
    elif total_score >= 30:
        verdict = "suspicious"
    else:
        verdict = "likely benign"

    all_iocs = list(dict.fromkeys(parsed["urls"] + parsed["ips"] + parsed["domains"]))

    result = {
        **parsed,
        "score": total_score,
        "verdict": verdict,
        "reasons": header_reasons + content_reasons,
        "extracted_iocs": all_iocs,
    }
    log.info(f"Triage verdict for {parsed['file']}: [bold]{verdict}[/bold] (score {total_score})")
    return result
