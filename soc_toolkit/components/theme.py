import streamlit as st


def metric_card(title, value, color="#00ff41"):
    html = (
        f'<div style="background:#1b1f2a;border-radius:18px;padding:20px;'
        f'border:1px solid {color};box-shadow:0 0 12px {color};'
        f'text-align:center;margin-bottom:15px;">'
        f'<div style="color:#8f9bb3;font-size:14px;font-weight:600;'
        f'text-transform:uppercase;">{title}</div>'
        f'<div style="color:white;font-size:28px;font-weight:bold;'
        f'margin-top:10px;">{value}</div>'
        f'</div>'
    )
    st.markdown(html, unsafe_allow_html=True)


def provider_card(provider, status, color):
    icon = "🟢" if status.lower() == "clean" else "🔴"
    html = (
        f'<div style="background:#151827;border-radius:15px;padding:18px;'
        f'border-left:6px solid {color};margin-bottom:12px;">'
        f'<h4 style="margin:0;color:white;">{icon} {provider}</h4>'
        f'<p style="margin-top:8px;color:#bfc7d5;">{status}</p>'
        f'</div>'
    )
    st.markdown(html, unsafe_allow_html=True)
