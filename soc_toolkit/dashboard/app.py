"""
SOC Toolkit — Streamlit Dashboard
==================================
Run with:  soc-toolkit dashboard
       or: streamlit run soc_toolkit/dashboard/app.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st

# Allow running this file directly with `streamlit run`
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from soc_toolkit.config import settings  # noqa: E402
from soc_toolkit.core import enrichment, phishing, report, yara_scan  # noqa: E402


st.set_page_config(
    page_title="SOC Toolkit",
    page_icon="🛡️",
    layout="wide"
)

# Debug outputs to help troubleshoot API key loading in the dashboard UI
st.write("VT API Loaded:", bool(settings.vt_api_key))
st.write("VT API Length:", len(settings.vt_api_key))

if settings.vt_api_key:
    st.write("VT Prefix:", settings.vt_api_key[:8])


# -----------------------------
# Load custom CSS
# -----------------------------

CSS_DIR = Path(__file__).resolve().parents[1] / "styles"
CSS_FILE = CSS_DIR / "style.css"
# Some repos ship the CSS as `style.css.txt` (e.g., for GitHub/viewer friendliness)
if not CSS_FILE.exists():
    CSS_FILE = CSS_DIR / "style.css.txt"


if CSS_FILE.exists():
    with open(CSS_FILE, "r", encoding="utf-8") as f:
        st.markdown(
            f"<style>{f.read()}</style>",
            unsafe_allow_html=True,
        )




VERDICT_COLORS = {

    "malicious": "🔴", "phishing": "🔴", "match": "🔴",
    "suspicious": "🟡",
    "clean": "🟢", "likely benign": "🟢",
    "unknown": "⚪", "unrecognized": "⚪",
}


def verdict_badge(verdict: str) -> str:
    return f"{VERDICT_COLORS.get(verdict, '⚪')} **{verdict.upper()}**"


with st.sidebar:
    st.title("🛡️ SOC Toolkit")
    st.caption("Python Tool for SOC / security analysts")
    page = st.radio(
        "Module",
        ["IOC Enrichment", "Phishing Triage", "YARA Scan", "About"]
    )

    st.divider()
    st.subheader("🛰️ Threat Intelligence Providers")

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
        "OpenCTI": bool(settings.opencti_token),
    }

    for provider, enabled in sources.items():
        status = "🟢" if enabled else "⚪"
        st.markdown(f"{status} **{provider}**")

    enabled = sum(sources.values())

    st.divider()
    st.metric(
        "Enabled Providers",
        f"{enabled}/{len(sources)}"
    )


    for name, ok in sources.items():
        st.write(f"{'✅' if ok else '⬜'} {name}")

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
        iocs = [line.strip() for line in raw_input.splitlines() if line.strip()]
        with st.spinner(f"Querying threat-intel sources for {len(iocs)} indicator(s)..."):
            results = enrichment.enrich_bulk(iocs)

        st.session_state["last_enrichment"] = results

        summary_rows = [
            {"IOC": r["ioc"], "Type": r["type"], "Verdict": r["verdict"], "Risk Score": r["risk_score"]}
            for r in results
        ]
        st.dataframe(pd.DataFrame(summary_rows), use_container_width=True)

        for r in results:
            with st.expander(f"{verdict_badge(r['verdict'])} — {r['ioc']}"):
                st.write(f"**Type:** {r['type']}  |  **Risk score:** {r['risk_score']}/100")
                if r["reasons"]:
                    st.write("**Reasons:**")
                    for reason in r["reasons"]:
                        st.write(f"- {reason}")
                for s in r["sources"]:
                    # Highlight authentication errors with a helpful message
                    if s.get("status") == "error" and "invalid" in s.get("reason", "").lower():
                        st.error(f"{s.get('source')}: Invalid API key or authentication failed. Check your `.env` and restart the app.")
                        st.json(s)
                    else:
                        st.json(s)

        if st.button("💾 Save HTML Report"):
            for r in results:
                path = report.generate_report(r, "enrichment", fmt="html")
                st.success(f"Saved: {path}")


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
        col1.metric("Verdict", result["verdict"].upper())
        col2.metric("Score", f"{result['score']}/100")

        st.subheader("Headers")
        st.json(result["headers"])

        st.subheader(f"Extracted IOCs ({len(result['extracted_iocs'])})")
        st.write(result["extracted_iocs"] or "None found.")

        st.subheader(f"Attachments ({len(result['attachments'])})")
        if result["attachments"]:
            st.dataframe(pd.DataFrame(result["attachments"]), use_container_width=True)
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
        """
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

