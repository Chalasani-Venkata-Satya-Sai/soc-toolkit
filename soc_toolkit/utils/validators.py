"""
Lightweight, dependency-free detection of IOC (Indicator of Compromise) types.

Supports: ipv4, ipv6, domain, url, md5, sha1, sha256, email
"""
from __future__ import annotations

import ipaddress
import re

_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
_URL_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", re.IGNORECASE)


class IOCType:
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    UNKNOWN = "unknown"


def detect_ioc_type(value: str) -> str:
    """Best-effort classification of a single indicator string."""
    value = value.strip()

    if not value:
        return IOCType.UNKNOWN

    # IP addresses
    try:
        ip_obj = ipaddress.ip_address(value)
        return IOCType.IPV4 if ip_obj.version == 4 else IOCType.IPV6
    except ValueError:
        pass

    # URL (has a scheme)
    if _URL_RE.match(value):
        return IOCType.URL

    # Hashes
    if _MD5_RE.match(value):
        return IOCType.MD5
    if _SHA1_RE.match(value):
        return IOCType.SHA1
    if _SHA256_RE.match(value):
        return IOCType.SHA256

    # Email
    if _EMAIL_RE.match(value):
        return IOCType.EMAIL

    # Domain (checked last since hashes/emails could look similar)
    if _DOMAIN_RE.match(value):
        return IOCType.DOMAIN

    return IOCType.UNKNOWN


def is_ip(value: str) -> bool:
    return detect_ioc_type(value) in (IOCType.IPV4, IOCType.IPV6)


def is_hash(value: str) -> bool:
    return detect_ioc_type(value) in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256)


def extract_domain_from_url(url: str) -> str | None:
    import tldextract

    ext = tldextract.extract(url)
    if not ext.domain:
        return None
    return ".".join(part for part in [ext.domain, ext.suffix] if part)
