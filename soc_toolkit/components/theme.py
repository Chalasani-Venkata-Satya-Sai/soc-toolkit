import streamlit as st


def metric_card(title, value, color="#00ff41"):
    html = (
        f'<div class="soc-metric-card" style="background:#1b1f2a;border-radius:18px;padding:20px;'
        f'border:1px solid {color};box-shadow:0 0 12px {color};'
        f'text-align:center;margin-bottom:15px;">'
        f'<div class="soc-metric-title">{title}</div>'
        f'<div class="soc-metric-value">{value}</div>'
        f'</div>'
    )
    st.markdown(html, unsafe_allow_html=True)


def provider_card(provider, status, color):
    icon = "🟢" if status.lower() == "clean" else "🔴"
    html = (
        f'<div class="soc-provider-card" style="background:#151827;border-radius:15px;padding:18px;'
        f'border-left:6px solid {color};margin-bottom:12px;">'
        f'<h4 class="soc-provider-name">{icon} {provider}</h4>'
        f'<p class="soc-provider-status">{status}</p>'
        f'</div>'
    )
    st.markdown(html, unsafe_allow_html=True)
