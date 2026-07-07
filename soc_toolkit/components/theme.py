"""
Reusable UI components for the SOC Toolkit dashboard.

Each function renders a small piece of HTML styled by
soc_toolkit/styles/style.css. Keep the HTML on a single line (no
leading whitespace per line) — Streamlit's Markdown renderer treats
4+ leading spaces as a code block and will print the raw tags instead
of parsing them as HTML.
"""

import streamlit as st

SEVERITY = {
    # verdict-ish keyword -> (badge/border color, css modifier)
    "malicious": ("critical", "#F0546A"),
    "phishing": ("critical", "#F0546A"),
    "match": ("critical", "#F0546A"),
    "suspicious": ("warning", "#F5A623"),
    "clean": ("clean", "#34D399"),
    "likely benign": ("clean", "#34D399"),
    "ok": ("clean", "#34D399"),
    "unknown": ("unknown", "#6B7688"),
    "unrecognized": ("unknown", "#6B7688"),
}


def severity_of(verdict: str) -> tuple[str, str]:
    """Map a verdict string to (css_class, hex_color) using the shared
    severity palette. css_class is one of: critical, warning, clean, unknown."""
    return SEVERITY.get((verdict or "").lower(), ("unknown", "#6B7688"))


# Backwards-compatible alias used internally.
_severity = severity_of


def metric_card(title, value, color=None, verdict=None):
    """A single stat card, e.g. 'Total Indicators — 12'.

    Pass either `color` (a hex string) directly, or `verdict` to derive
    the accent color from the shared severity palette.
    """
    if color is None:
        _, color = _severity(verdict) if verdict else ("unknown", "#4FA8FF")
    html = (
        f'<div class="soc-metric-card" style="--card-accent:{color};">'
        f'<div class="soc-metric-title">{title}</div>'
        f'<div class="soc-metric-value">{value}</div>'
        f'</div>'
    )
    st.markdown(html, unsafe_allow_html=True)


def provider_card(provider, status, color=None):
    css_class, default_color = _severity(status)
    color = color or default_color
    icon = "●"
    html = (
        f'<div class="soc-provider-card" style="--card-accent:{color};">'
        f'<h4 class="soc-provider-name">{provider}</h4>'
        f'<p class="soc-provider-status">{icon} {status}</p>'
        f'</div>'
    )
    st.markdown(html, unsafe_allow_html=True)


def verdict_badge(verdict: str) -> str:
    """Return an HTML pill badge for a verdict string (malicious/suspicious/clean/unknown)."""
    css_class, _ = _severity(verdict)
    label = (verdict or "unknown").upper()
    return (
        f'<span class="soc-badge soc-badge-{css_class}">'
        f'<span class="soc-badge-dot"></span>{label}</span>'
    )


def status_rail(title: str, subtitle: str, right_text: str, healthy: bool = True):
    """The header status rail — the dashboard's signature element.

    Renders a slim console-style bar: a live status dot, a title/subtitle,
    and a right-aligned detail (e.g. source count).
    """
    dot_color = "#34D399" if healthy else "#F5A623"
    html = (
        f'<div class="soc-status-rail">'
        f'<div class="soc-status-rail-left">'
        f'<span class="soc-status-dot" style="background:{dot_color};'
        f'box-shadow:0 0 0 4px {dot_color}22;"></span>'
        f'<span class="soc-status-title">{title}</span>'
        f'<span class="soc-status-sub">{subtitle}</span>'
        f'</div>'
        f'<div class="soc-status-rail-right">{right_text}</div>'
        f'</div>'
    )
    st.markdown(html, unsafe_allow_html=True)


def source_row(name: str, enabled: bool) -> str:
    """Return an HTML row for the compact sidebar provider list."""
    state = "soc-source-on" if enabled else "soc-source-off"
    return (
        f'<div class="soc-source-row {state}">'
        f'<span class="soc-source-dot"></span>{name}</div>'
    )
