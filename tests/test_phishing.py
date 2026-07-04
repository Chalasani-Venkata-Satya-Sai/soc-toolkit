from pathlib import Path

from soc_toolkit.core.phishing import parse_eml, triage_email

SAMPLE = Path(__file__).resolve().parent.parent / "sample_data" / "sample_phishing.eml"


def test_parse_eml_extracts_headers():
    parsed = parse_eml(SAMPLE)
    assert "IT Support Desk" in parsed["headers"]["from"]
    assert parsed["headers"]["subject"].startswith("URGENT")


def test_parse_eml_extracts_urls_and_ips():
    parsed = parse_eml(SAMPLE)
    assert any("192.168.44.10" in url for url in parsed["urls"])
    assert "192.168.44.10" in parsed["ips"]


def test_parse_eml_extracts_attachments():
    parsed = parse_eml(SAMPLE)
    assert len(parsed["attachments"]) == 1
    assert parsed["attachments"][0]["filename"] == "invoice_details.js"
    assert parsed["attachments"][0]["sha256"] is not None


def test_triage_email_flags_as_suspicious_or_worse():
    result = triage_email(SAMPLE)
    assert result["verdict"] in ("suspicious", "phishing")
    assert result["score"] > 0
    assert len(result["reasons"]) > 0
    assert len(result["extracted_iocs"]) > 0
