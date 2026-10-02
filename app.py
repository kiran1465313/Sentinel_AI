import json

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from src.vpn_sentinel import (
    generate_executive_report_html,
    get_session_summary,
    load_demo_profiles,
    parse_uploaded_profile,
    score_profile,
)

st.set_page_config(page_title="VPN Sentinel AI", page_icon="🛡️", layout="wide")

st.markdown(
    """
    <style>
        .main {
            background: linear-gradient(180deg, #f8fbff 0%, #eef4ff 100%);
        }
        .metric-card {
            background: rgba(17, 24, 39, 0.03);
            border: 1px solid rgba(148, 163, 184, 0.2);
            padding: 1rem 1.2rem;
            border-radius: 14px;
            box-shadow: 0 4px 12px rgba(15, 23, 42, 0.04);
        }
        .profile-panel {
            background: white;
            border: 1px solid rgba(148, 163, 184, 0.3);
            border-radius: 16px;
            padding: 1rem 1.15rem;
            box-shadow: 0 8px 24px rgba(15, 23, 42, 0.06);
        }
        .pill {
            display: inline-block;
            background: #dbeafe;
            color: #1d4ed8;
            border-radius: 999px;
            padding: 0.28rem 0.7rem;
            font-size: 0.78rem;
            font-weight: 700;
        }
    </style>
    """,
    unsafe_allow_html=True,
)


def risk_gauge(score: int):
    color = "#22c55e" if score < 25 else "#f59e0b" if score < 60 else "#ef4444"
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            domain={"x": [0, 1], "y": [0, 1]},
            title={"text": f"Risk score: {score}/100"},
            gauge={
                "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "darkblue"},
                "bar": {"color": color},
                "bgcolor": "white",
                "borderwidth": 2,
                "bordercolor": "gray",
                "steps": [
                    {"range": [0, 25], "color": "#dcfce7"},
                    {"range": [25, 60], "color": "#fef3c7"},
                    {"range": [60, 100], "color": "#fee2e2"},
                ],
            },
        )
    )
    fig.update_layout(height=260, margin=dict(l=20, r=20, t=40, b=20), paper_bgcolor="rgba(0,0,0,0)")
    return fig


def build_overview(profile: dict, session: dict):
    st.subheader("Overview")

    col1, col2, col3, col4 = st.columns(4)
    col1.markdown(
        """
        <div class="metric-card">
            <div class="pill">Sessions</div>
            <h3 style="margin-top: 0.5rem; margin-bottom: 0;">{}</h3>
        </div>
        """.format(session["session_count"]),
        unsafe_allow_html=True,
    )
    col2.markdown(
        """
        <div class="metric-card">
            <div class="pill">IPsec</div>
            <h3 style="margin-top: 0.5rem; margin-bottom: 0;">{}</h3>
        </div>
        """.format("Yes" if session["ipsec_detected"] else "No"),
        unsafe_allow_html=True,
    )
    col3.markdown(
        """
        <div class="metric-card">
            <div class="pill">IKE</div>
            <h3 style="margin-top: 0.5rem; margin-bottom: 0;">{}</h3>
        </div>
        """.format(session["ike_version"]),
        unsafe_allow_html=True,
    )
    col4.markdown(
        """
        <div class="metric-card">
            <div class="pill">Risk</div>
            <h3 style="margin-top: 0.5rem; margin-bottom: 0;">{}/100</h3>
        </div>
        """.format(session["security_score"]),
        unsafe_allow_html=True,
    )

    left, right = st.columns([1.7, 1.2])
    with left:
        st.plotly_chart(risk_gauge(session["security_score"]), use_container_width=True)
    with right:
        st.markdown("### Analyst verdict")
        st.markdown(f"<div class='profile-panel'><h3>{session['risk_label']}</h3><p>Traffic class: <strong>{session['traffic_prediction']}</strong></p><p>Confidence: <strong>{session['confidence']:.2f}%</strong></p></div>", unsafe_allow_html=True)
        st.write("")
        st.write("The tool separates observed facts from probabilistic traffic inference.")

    st.markdown("### Configuration comparison")
    demo_profiles = load_demo_profiles()
    legacy_score = score_profile(demo_profiles["legacy"])["score"]
    hardened_score = score_profile(demo_profiles["hardened"])["score"]

    comp_cols = st.columns(2)
    with comp_cols[0]:
        st.markdown(
            """
            <div class='profile-panel'>
                <h4>Legacy-risk profile</h4>
                <div class='pill'>High risk</div>
                <ul>
                    <li>IKEv1</li>
                    <li>AES-CBC + SHA-1</li>
                    <li>DH Group 2</li>
                    <li>PFS disabled</li>
                </ul>
                <h3>{}/100</h3>
            </div>
            """.format(legacy_score),
            unsafe_allow_html=True,
        )
    with comp_cols[1]:
        st.markdown(
            """
            <div class='profile-panel'>
                <h4>Hardened profile</h4>
                <div class='pill'>Low risk</div>
                <ul>
                    <li>IKEv2</li>
                    <li>AES-256-GCM</li>
                    <li>DH Group 14</li>
                    <li>PFS enabled</li>
                </ul>
                <h3>{}/100</h3>
            </div>
            """.format(hardened_score),
            unsafe_allow_html=True,
        )


def build_intelligence(profile: dict, session: dict):
    st.subheader("VPN Intelligence")
    cols = st.columns(3)
    cols[0].metric("IKE version", profile.get("ike_version", "unknown"))
    cols[1].metric("Tunnel / transport estimate", profile.get("tunnel_mode", "tunnel"))
    cols[2].metric("NAT traversal", "Yes" if profile.get("nat_t") else "No")

    st.markdown("### SA / SPI table")
    sa_data = profile.get("spi_values", ["N/A"])
    sa_df = pd.DataFrame(
        {
            "SA ID": [f"SA-{idx + 1}" for idx in range(len(sa_data))],
            "SPI": sa_data,
            "Direction": ["Inbound" if idx % 2 == 0 else "Outbound" for idx in range(len(sa_data))],
        }
    )
    st.dataframe(sa_df, use_container_width=True)

    crypto = profile.get("crypto", {})
    st.markdown("### Crypto configuration card")
    detail_df = pd.DataFrame(
        {
            "Field": ["Encryption", "Integrity", "DH group", "PFS", "Rekey lifetime", "Proposal"],
            "Value": [
                crypto.get("encryption", "unknown"),
                crypto.get("integrity", "unknown"),
                crypto.get("dh_group", "unknown"),
                crypto.get("pfs", "unknown"),
                f"{crypto.get('rekey_lifetime_seconds', 0)} sec",
                crypto.get("ike_proposal", "unknown"),
            ],
        },
    )
    st.dataframe(detail_df, use_container_width=True)


def build_threat_matrix(profile: dict, session: dict):
    st.subheader("Threat Matrix")
    findings = session["score_result"]["findings"]
    if not findings:
        st.info("No findings were generated for this profile.")
        return

    threat_df = pd.DataFrame(findings)
    threat_df = threat_df[["finding", "severity", "evidence", "impact", "fix", "points"]]
    st.dataframe(threat_df, use_container_width=True)

    st.markdown("### Explainability summary")
    st.write(
        "Each finding is tied to specific evidence, expected impact, and a clear remediation path. This is intentionally transparent for analyst review."
    )


def build_traffic_intelligence(profile: dict, session: dict):
    st.subheader("Traffic Intelligence")
    flow = profile.get("flow", {})
    prediction = session["flow_prediction"]

    col_a, col_b = st.columns(2)
    col_a.markdown(f"### Predicted traffic category: **{prediction['label']}**")
    col_b.markdown(f"### Confidence: **{prediction['confidence']:.2f}%**")

    feature_importance = prediction.get("feature_importance", {})
    if feature_importance:
        fi_df = pd.DataFrame({"feature": list(feature_importance.keys()), "importance": list(feature_importance.values())})
        fi_df = fi_df.sort_values("importance", ascending=False)
        fi_fig = px.bar(fi_df, x="feature", y="importance", title="Feature importance")
        st.plotly_chart(fi_fig, use_container_width=True)

    timeline = flow.get("timeline", [0, 1, 2, 3])
    packet_sizes = flow.get("packet_sizes", [64, 128, 256, 512])
    t_fig = px.line(x=list(range(len(timeline))), y=timeline, title="Flow timeline")
    st.plotly_chart(t_fig, use_container_width=True)

    p_fig = px.histogram(x=packet_sizes, nbins=20, title="Packet-size distribution")
    st.plotly_chart(p_fig, use_container_width=True)

    st.markdown("### Explainability card")
    st.info(prediction["explanation"])


def main():
    st.title("VPN Sentinel AI")
    st.caption("From encrypted packets to explainable IPsec security decisions.")

    with st.sidebar:
        st.header("Session Input")
        uploaded_file = st.file_uploader("Upload PCAP or JSON metadata", type=["pcap", "json", "csv"])
        demo_profiles = load_demo_profiles()
        selected_profile_name = st.selectbox(
            "Demo profile",
            ["Legacy-risk profile", "Hardened profile"],
            index=0,
        )
        profile_source = st.radio("Choose source", ["Demo profile", "Uploaded file"])
        st.markdown("---")
        st.caption(
            '"ESP encrypts payload content, so our classifier does not claim payload decryption. It estimates traffic behavior from flow-level metadata and presents a confidence score."'
        )

    if profile_source == "Uploaded file" and uploaded_file is not None:
        profile = parse_uploaded_profile(uploaded_file)
        if not profile:
            st.warning("The uploaded file could not be parsed. Please upload a JSON/CSV profile or a small PCAP sample.")
            profile = demo_profiles["legacy"]
    else:
        profile = demo_profiles["legacy"] if selected_profile_name == "Legacy-risk profile" else demo_profiles["hardened"]

    session = get_session_summary(profile)

    report = {
        "profile": profile.get("profile_name", "Current Session"),
        "score": session["security_score"],
        "risk_label": session["risk_label"],
        "traffic_prediction": session["traffic_prediction"],
        "confidence": session["confidence"],
        "findings": session["score_result"]["findings"],
        "explainability": session["flow_prediction"]["explanation"],
    }

    btn_col1, btn_col2 = st.columns([1, 1])
    with btn_col1:
        st.download_button(
            "Download JSON report",
            data=json.dumps(report, indent=2),
            file_name="vpn_sentinel_report.json",
            mime="application/json",
        )
    with btn_col2:
        st.download_button(
            "Download HTML report",
            data=generate_executive_report_html(session, profile),
            file_name="vpn_sentinel_report.html",
            mime="text/html",
        )

    tabs = st.tabs(["Overview", "VPN Intelligence", "Threat Matrix", "Traffic Intelligence"])
    with tabs[0]:
        build_overview(profile, session)
    with tabs[1]:
        build_intelligence(profile, session)
    with tabs[2]:
        build_threat_matrix(profile, session)
    with tabs[3]:
        build_traffic_intelligence(profile, session)


if __name__ == "__main__":
    main()
