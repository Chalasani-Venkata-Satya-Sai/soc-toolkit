"""
SOC Toolkit — Streamlit Dashboard
==================================
Run with:  soc-toolkit dashboard
       or: streamlit run soc_toolkit/dashboard/app.py
"""
from __future__ import annotations

import sys
import tempfile
import textwrap
from pathlib import Path

import pandas as pd
import streamlit as st

# Allow running this file directly with `streamlit run` — this MUST happen
# before any `soc_toolkit.*` imports below, since Streamlit puts this
# script's own directory on sys.path, not the project root.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from soc_toolkit.components.theme import (
    metric_card,
    provider_card,
    severity_of,
    source_row,
    status_rail,
    verdict_badge,
)
from soc_toolkit.config import settings
from soc_toolkit.core import enrichment, phishing, report, yara_scan

st.set_page_config(
    page_title="SOC Toolkit",
    page_icon="🛡️",
    layout="wide",
)

# -----------------------------
# Load custom CSS (must run before any other st.* rendering below)
# -----------------------------

CSS_DIR = Path(__file__).resolve().parents[1] / "styles"
CSS_FILE = CSS_DIR / "style.css"
# Some repos ship the CSS as `style.css.txt` (e.g., for GitHub/viewer friendliness)
if not CSS_FILE.exists():
    CSS_FILE = CSS_DIR / "style.css.txt"

if CSS_FILE.exists():
    with open(CSS_FILE, "r", encoding="utf-8") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)




EMOJI_BY_SEVERITY = {"critical": "🔴", "warning": "🟡", "clean": "🟢", "unknown": "⚪"}


def verdict_label(verdict: str) -> str:
    """Plain-text verdict label for contexts that can't render HTML
    (e.g. st.expander headers, which only accept plain text/markdown-lite)."""
    css_class, _ = severity_of(verdict)
    emoji = EMOJI_BY_SEVERITY.get(css_class, "⚪")
    return f"{emoji} {(verdict or 'unknown').upper()}"


with st.sidebar:
    st.markdown(
        '<div style="font-family:var(--font-ui);font-weight:700;font-size:20px;">'
        '🛡️ SOC Toolkit</div>',
        unsafe_allow_html=True,
    )
    st.caption("Automation toolkit for SOC / security analysts")
    page = st.radio(
        "Module",
        ["IOC Enrichment", "Phishing Triage", "YARA Scan", "About"],
        label_visibility="collapsed",
    )

    st.divider()
    st.markdown(
        '<div class="soc-status-title" style="margin-bottom:8px;">'
        '🛰️ THREAT INTEL PROVIDERS</div>',
        unsafe_allow_html=True,
    )

    sources = {
        "OpenCTI": bool(settings.opencti_token),
        "VirusTotal": bool(settings.vt_api_key),
        "AbuseIPDB": bool(settings.abuseipdb_api_key),
        "Shodan": bool(settings.shodan_api_key),
        "IBM X-Force": bool(settings.xforce_api_key),
        "AlienVault OTX": bool(settings.otx_api_key),
        "Pulsedive": bool(settings.pulsedive_api_key),
        "Censys": bool(settings.censys_api_id),
        "ZoomEye": bool(settings.zoomeye_api_key),
        "Cisco Talos": bool(settings.talos_api_key),
        "PhishTank": bool(settings.phishtank_api_key),
        "Google Safe Browsing": bool(settings.gsb_api_key),
        "URLScan": bool(settings.urlscan_api_key),
        "URLHaus": bool(settings.urlhaus_api_key),
        "Hybrid Analysis": bool(settings.hybrid_analysis_api_key),
        "GreyNoise": bool(settings.greynoise_api_key),
        "MISP": bool(settings.misp_api_key),
    }

    grid_html = '<div class="soc-source-grid">' + "".join(
        source_row(name, ok) for name, ok in sources.items()
    ) + "</div>"
    st.markdown(grid_html, unsafe_allow_html=True)

    enabled = sum(sources.values())

    st.divider()
    st.metric("Enabled Providers", f"{enabled}/{len(sources)}")

    # Provide a one-click validation tool to diagnose bad/invalid API keys.
    if st.button("Validate API keys"):
        st.info("Validating configured API keys...")
        checks: list[tuple[str, dict]] = []

        # VirusTotal (domain check)
        if settings.vt_api_key:
            try:
                vt_res = enrichment.check_virustotal("example.com", enrichment.IOCType.DOMAIN)
            except Exception as exc:  # pragma: no cover - defensive
                vt_res = {"source": "virustotal", "status": "error", "reason": str(exc)}
            checks.append(("VirusTotal", vt_res))
        else:
            checks.append(("VirusTotal", {"status": "skipped", "reason": "no API key"}))

        # AbuseIPDB (IP check)
        if settings.abuseipdb_api_key:
            try:
                abuse_res = enrichment.check_abuseipdb("8.8.8.8")
            except Exception as exc:  # pragma: no cover - defensive
                abuse_res = {"source": "abuseipdb", "status": "error", "reason": str(exc)}
            checks.append(("AbuseIPDB", abuse_res))
        else:
            checks.append(("AbuseIPDB", {"status": "skipped", "reason": "no API key"}))

        # Shodan (IP check)
        if settings.shodan_api_key:
            try:
                shodan_res = enrichment.check_shodan("8.8.8.8")
            except Exception as exc:  # pragma: no cover - defensive
                shodan_res = {"source": "shodan", "status": "error", "reason": str(exc)}
            checks.append(("Shodan", shodan_res))
        else:
            checks.append(("Shodan", {"status": "skipped", "reason": "no API key"}))

        # Display results
        for name, res in checks:
            status = res.get("status")
            reason = res.get("reason", "")
            if status == "ok":
                st.success(f"{name}: OK")
            elif status == "skipped":
                st.warning(f"{name}: no API key configured")
            else:
                st.error(f"{name}: {reason}")

    if not any(sources.values()):
        st.warning("No API keys configured. Add them to `.env` (see `.env.example`).")

# ---------------------------------------------------------------------------
# Status rail — signature element shown at the top of every page
# ---------------------------------------------------------------------------
_provider_count = sum(sources.values())
status_rail(
    title="SOC TOOLKIT",
    subtitle=page,
    right_text=f"{_provider_count}/{len(sources)} SOURCES ONLINE",
    healthy=_provider_count > 0,
)



# ---------------------------------------------------------------------------
# IOC Enrichment
# ---------------------------------------------------------------------------
if page == "IOC Enrichment":
    st.header("🔍 IOC Enrichment")
    st.caption("Look up IPs, domains, URLs, or file hashes across multiple threat-intel sources at once.")

    raw_input = st.text_area(
        "Enter one or more indicators (one per line)",
        placeholder="8.8.8.8\nexample.com\n44d88612fea8a8f36de82e1278abb02f",
        height=120,
    )

    if st.button("Enrich Indicators", type="primary") and raw_input.strip():
        indicators = [line.strip() for line in raw_input.splitlines() if line.strip()]

        with st.spinner(f"Enriching {len(indicators)} indicator(s)..."):
            results = enrichment.enrich_bulk(indicators)

        st.session_state["last_enrichment"] = results

        malicious_count = sum(1 for r in results if r["verdict"] in ("malicious", "phishing", "match"))
        suspicious_count = sum(1 for r in results if r["verdict"] == "suspicious")
        clean_count = sum(1 for r in results if r["verdict"] == "clean")
        unknown_count = len(results) - malicious_count - suspicious_count - clean_count

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            metric_card("Total Indicators", len(results), color="#4FA8FF")
        with col2:
            metric_card("Malicious", malicious_count, color="#F0546A")
        with col3:
            metric_card("Suspicious", suspicious_count, color="#F5A623")
        with col4:
            metric_card("Clean / Unknown", clean_count + unknown_count, color="#34D399")

        st.subheader("Summary")
        summary_rows = [
            {
                "IOC": r["ioc"],
                "Type": r["type"],
                "Verdict": r["verdict"],
                "Risk Score": r["risk_score"],
            }
            for r in results
        ]
        st.dataframe(pd.DataFrame(summary_rows), width='stretch')

        st.subheader("Details")
        for r in results:
            # st.expander labels are plain text, not HTML — use the emoji
            # variant here; the HTML pill badge is used inside the body below.
            with st.expander(f"{verdict_label(r['verdict'])} — {r['ioc']}"):
                st.markdown(verdict_badge(r["verdict"]), unsafe_allow_html=True)
                for reason in r.get("reasons", []):
                    st.write(f"- {reason}")

                for src in r.get("sources", []):
                    status = src.get("status", "unknown")
                    provider_card(src.get("source", "unknown").title(), status)
                    extra = {k: v for k, v in src.items() if k not in ("source", "status")}
                    if extra:
                        st.json(extra)

        if st.button("💾 Save HTML Report"):
            saved_paths = [
                report.generate_report(r, "enrichment", fmt="html") for r in results
            ]
            st.success("Saved: " + ", ".join(str(p) for p in saved_paths))


# ---------------------------------------------------------------------------
# Phishing Triage
# ---------------------------------------------------------------------------
elif page == "Phishing Triage":
    st.header("📧 Phishing Email Triage")
    st.caption("Upload a raw .eml file to extract headers, IOCs, and get an automated verdict.")

    uploaded = st.file_uploader("Upload .eml file", type=["eml"])
    enrich_toggle = st.checkbox("Also enrich extracted IOCs with threat intel", value=False)

    if uploaded and st.button("Run Triage", type="primary"):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp:
            tmp.write(uploaded.read())
            tmp_path = tmp.name

        with st.spinner("Parsing and scoring email..."):
            result = phishing.triage_email(tmp_path)
            if enrich_toggle and result["extracted_iocs"]:
                result["ioc_enrichment"] = enrichment.enrich_bulk(result["extracted_iocs"])

        st.session_state["last_phishing"] = result

        col1, col2 = st.columns(2)
        with col1:
            metric_card("Verdict", result["verdict"].upper(), verdict=result["verdict"])
        with col2:
            metric_card("Score", f"{result['score']}/100", color="#4FA8FF")

        st.markdown(verdict_badge(result["verdict"]), unsafe_allow_html=True)

        st.subheader("Headers")
        st.json(result["headers"])

        st.subheader(f"Extracted IOCs ({len(result['extracted_iocs'])})")
        st.write(result["extracted_iocs"] or "None found.")

        st.subheader(f"Attachments ({len(result['attachments'])})")
        if result["attachments"]:
            st.dataframe(pd.DataFrame(result["attachments"]), width='stretch')
        else:
            st.write("None found.")

        st.subheader("Reasons")
        for r in result["reasons"]:
            st.write(f"- {r}")

        if st.button("💾 Save HTML Report"):
            path = report.generate_report(result, "phishing", fmt="html")
            st.success(f"Saved: {path}")


# ---------------------------------------------------------------------------
# YARA Scan
# ---------------------------------------------------------------------------
elif page == "YARA Scan":
    st.header("🧬 YARA Malware Scan")
    st.caption("Scan an uploaded file against the bundled (or custom) YARA rule set.")

    uploaded = st.file_uploader("Upload a file to scan", type=None)

    if uploaded and st.button("Scan File", type="primary"):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(uploaded.read())
            tmp_path = tmp.name

        with st.spinner("Compiling rules and scanning..."):
            result = yara_scan.scan(tmp_path)

        match_found = result["matches_found"] > 0
        st.metric("Matches Found", result["matches_found"])

        for r in result["results"]:
            if r["status"] == "match":
                st.error(f"MATCH: {uploaded.name}")
                for m in r["matches"]:
                    st.write(f"**Rule:** {m['rule']}  |  **Tags:** {', '.join(m['tags'])}")
                    st.json(m["meta"])
            elif r["status"] == "clean":
                st.success(f"No matches: {uploaded.name}")
            else:
                st.warning(f"{r['status']}: {r.get('reason', '')}")

        if st.button("💾 Save HTML Report"):
            path = report.generate_report(result, "yara", fmt="html")
            st.success(f"Saved: {path}")


# ---------------------------------------------------------------------------
# About
# ---------------------------------------------------------------------------
else:
    st.header("About SOC Toolkit")
    st.markdown(
        textwrap.dedent(
            """\
            **SOC Toolkit** is an all-in-one Python automation platform for
            SOC / security analysts, combining:

            - 🔍 **IOC Enrichment** — VirusTotal, AbuseIPDB, and Shodan lookups with a rolled-up risk verdict
            - 📧 **Phishing Triage** — header-spoofing detection, IOC extraction, and attachment hashing from raw `.eml` files
            - 🧬 **YARA Scanning** — file/endpoint malware pattern matching
            - 📄 **Reporting** — JSON and styled HTML reports ready for tickets or SIEM ingestion

            Available both as a **CLI** (`soc-toolkit --help`) and this dashboard.

            See the project `README.md` for full setup and API key configuration.
            """
        )
    )
