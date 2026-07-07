from unittest.mock import MagicMock, patch

from soc_toolkit.core import enrichment


def test_enrich_ioc_skips_when_no_api_keys():
    # Ensure enabled_sources reports no providers during this test
    with patch.object(enrichment.settings, "vt_api_key", ""), \
         patch.object(enrichment.settings, "abuseipdb_api_key", ""), \
         patch.object(enrichment.settings, "shodan_api_key", ""), \
         patch.object(enrichment.settings, "enabled_sources", return_value=[]):
        result = enrichment.enrich_ioc("8.8.8.8")

    assert result["ioc"] == "8.8.8.8"
    assert result["type"] == "ipv4"
    # With early return when no providers are enabled, sources should be empty
    assert result["sources"] == []
    assert result["verdict"] == "unknown"


def test_enrich_ioc_unknown_type_short_circuits():
    result = enrichment.enrich_ioc("!!not-an-ioc??")
    assert result["verdict"] == "unrecognized"
    assert result["sources"] == []


@patch("soc_toolkit.core.enrichment.requests.get")
def test_check_virustotal_ok_response(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.ok = True
    mock_resp.json.return_value = {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 5, "suspicious": 1, "harmless": 60, "undetected": 10}}}
    }
    mock_get.return_value = mock_resp

    with patch.object(enrichment.settings, "vt_api_key", "fake-key"):
        result = enrichment.check_virustotal("8.8.8.8", "ipv4")

    assert result["status"] == "ok"
    assert result["malicious"] == 5


def test_compute_verdict_malicious_when_high_score():
    sources = [{"source": "virustotal", "status": "ok", "malicious": 10}]
    verdict = enrichment._compute_verdict(sources)
    assert verdict["verdict"] == "malicious"
    assert verdict["risk_score"] > 0
