import streamlit as st


def metric_card(title, value, color="#00ff41"):
    st.markdown(
        f"""
        <div style="
            background:#1b1f2a;
            border-radius:18px;
            padding:20px;
            border:1px solid {color};
            box-shadow:0 0 12px {color};
            text-align:center;
            margin-bottom:15px;
        ">

            <div style="
                color:#8f9bb3;
                font-size:14px;
                font-weight:600;
                text-transform:uppercase;
            ">
                {title}
            </div>

            <div style="
                color:white;
                font-size:28px;
                font-weight:bold;
                margin-top:10px;
            ">
                {value}
            </div>

        </div>
        """,
        unsafe_allow_html=True,
    )


def provider_card(provider, status, color):

    icon = "🟢" if status.lower() == "clean" else "🔴"

    st.markdown(
        f"""
        <div style="
            background:#151827;
            border-radius:15px;
            padding:18px;
            border-left:6px solid {color};
            margin-bottom:12px;
        ">

            <h4 style="margin:0;color:white;">
                {icon} {provider}
            </h4>

            <p style="
                margin-top:8px;
                color:#bfc7d5;
            ">
                {status}
            </p>

        </div>
        """,
        unsafe_allow_html=True,
    )
