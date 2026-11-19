import streamlit as st
import pandas as pd
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from backend.dashboard import get_dashboard_data, get_recent_events
from backend.zero_trust import (
    initialize_zero_trust,
    evaluate_access,
    get_access_logs
)

st.set_page_config(
    page_title="ResiNet-IDAM",
    page_icon="🛡️",
    layout="wide"
)

# Initialize the audit database
initialize_zero_trust()

# Custom styling
st.markdown("""
<style>
.stApp {
    background-color: #080d18;
    color: #e8eefc;
}
[data-testid="stSidebar"] {
    background-color: #101a2c;
}
h1, h2, h3 {
    color: #62d5ff !important;
}
div[data-testid="stMetric"] {
    background: #14243b;
    border: 1px solid #244365;
    padding: 18px;
    border-radius: 12px;
}
.stButton button {
    background-color: #087fa8;
    color: white;
    border-radius: 8px;
}
</style>
""", unsafe_allow_html=True)

st.sidebar.title("🛡️ ResiNet-IDAM")
st.sidebar.caption("Adaptive Intrusion Detection & Zero-Trust")

page = st.sidebar.radio(
    "NAVIGATION",
    [
        "Security Dashboard",
        "AI Intrusion Detection",
        "IT Dataset Explorer",
        "Identity & Access",
        "Zero-Trust Security",
        "Adaptive Monitoring",
        "Reports & Audit Logs"
    ]
)

st.sidebar.divider()
st.sidebar.caption("Academic IT Security Prototype")
st.sidebar.caption("Demo data — not live network monitoring")

# --------------------------------------------------
# SECURITY DASHBOARD
# --------------------------------------------------

if page == "Security Dashboard":

    st.title("🛡️ Security Operations Dashboard")
    st.write("ResiNet-IDAM — Intelligent IT Threat Defense Platform")

    data = get_dashboard_data()

    st.info("DEMO MODE: Dashboard values are illustrative demonstration data.")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Network Events", data["network_events"])
    col2.metric("Threats Detected", data["threats_detected"])
    col3.metric("Access Allowed", data["access_allowed"])
    col4.metric("Access Denied", data["access_denied"])

    st.subheader("System Risk Overview")
    st.progress(data["risk_score"])
    st.write(f"Current demonstration risk score: {data['risk_score']}%")

    left, right = st.columns(2)

    with left:
        st.subheader("Threat Distribution")
        threat_df = pd.DataFrame(data["threat_distribution"])
        st.bar_chart(threat_df.set_index("label"))

    with right:
        st.subheader("Network Traffic Overview")
        traffic_df = pd.DataFrame(data["traffic"])
        st.line_chart(traffic_df.set_index("time"))

    st.subheader("Recent Security Events")
    st.dataframe(
        pd.DataFrame(get_recent_events()),
        use_container_width=True
    )

# --------------------------------------------------
# AI INTRUSION DETECTION
# --------------------------------------------------

elif page == "AI Intrusion Detection":

    st.title("🤖 AI Intrusion Detection")
    st.write("Machine-learning-based IT intrusion classification.")

    st.warning(
        "This page requires the existing backend model and a suitable IT dataset. "
        "The live model integration will be added in the next step."
    )

    st.subheader("Detection Overview")

    col1, col2 = st.columns(2)
    col1.metric("Detection Algorithm", "Random Forest")
    col2.metric("Dataset Type", "IT Network Data")

    st.info("Model training and prediction controls will be connected next.")

# --------------------------------------------------
# IT DATASET EXPLORER
# --------------------------------------------------

elif page == "IT Dataset Explorer":

    st.title("📁 IT Dataset Explorer")
    st.write("Upload and inspect an IT intrusion-detection CSV dataset.")

    uploaded_file = st.file_uploader(
        "Upload IT Dataset (CSV)",
        type=["csv"]
    )

    if uploaded_file is not None:
        try:
            df = pd.read_csv(uploaded_file)

            st.success("Dataset uploaded successfully.")

            col1, col2, col3 = st.columns(3)
            col1.metric("Total Rows", len(df))
            col2.metric("Total Columns", len(df.columns))
            col3.metric("Missing Values", int(df.isnull().sum().sum()))

            st.subheader("Dataset Preview")
            st.dataframe(df.head(100), use_container_width=True)

            st.subheader("Dataset Information")
            st.write("Column names:")
            st.write(list(df.columns))

            st.subheader("Statistical Summary")
            st.dataframe(df.describe(include="all"), use_container_width=True)

        except Exception as error:
            st.error(f"Unable to read dataset: {error}")

    else:
        st.info("Upload a CSV file to explore the dataset.")

# --------------------------------------------------
# IDENTITY AND ACCESS
# --------------------------------------------------

elif page == "Identity & Access":

    st.title("👤 Identity & Access Management")

    st.write(
        "Identity and access controls are demonstrated through "
        "the Zero-Trust evaluation module."
    )

    st.subheader("Access Control Principles")

    st.markdown("""
    - Identity verification
    - Role-based access
    - Device trust validation
    - Multi-factor authentication
    - Risk-based access decisions
    """)

    st.info("Use the Zero-Trust Security page to evaluate an access request.")

# --------------------------------------------------
# ZERO TRUST SECURITY
# --------------------------------------------------

elif page == "Zero-Trust Security":

    st.title("🔐 Zero-Trust Security Evaluation")

    st.write("Evaluate access using identity, device, MFA and risk conditions.")

    with st.form("zero_trust_form"):

        username = st.text_input("Username", value="admin")
        role = st.selectbox(
            "User Role",
            ["administrator", "analyst", "viewer", "student"]
        )
        resource = st.selectbox(
            "Requested Resource",
            [
                "security_dashboard",
                "dataset_explorer",
                "intrusion_detection",
                "audit_logs"
            ]
        )

        device_trusted = st.checkbox("Trusted Device", value=True)
        mfa_verified = st.checkbox("MFA Verified", value=True)

        risk_score = st.slider(
            "Risk Score",
            min_value=0,
            max_value=100,
            value=20
        )

        submitted = st.form_submit_button("Evaluate Access")

    if submitted:

        request_data = {
            "username": username,
            "role": role,
            "resource": resource,
            "device_trusted": device_trusted,
            "mfa_verified": mfa_verified,
            "risk_score": risk_score
        }

        try:
            result = evaluate_access(request_data)

            if result["decision"] == "ALLOW":
                st.success("ACCESS ALLOWED")
            else:
                st.error("ACCESS DENIED")

            st.write("Reason:", result["reason"])
            st.write("Audit Log ID:", result["log_id"])
            st.write("Timestamp:", result["timestamp"])

        except Exception as error:
            st.error(f"Evaluation failed: {error}")

# --------------------------------------------------
# ADAPTIVE MONITORING
# --------------------------------------------------

elif page == "Adaptive Monitoring":

    st.title("📡 Adaptive Security Monitoring")

    st.write(
        "Demonstration of risk-based monitoring and adaptive security decisions."
    )

    data = get_dashboard_data()

    st.metric("Current Risk Score", f"{data['risk_score']}%")

    if data["risk_score"] >= 70:
        st.error("High-risk condition: additional verification recommended.")
    elif data["risk_score"] >= 40:
        st.warning("Medium-risk condition: monitor activity.")
    else:
        st.success("Low-risk demonstration condition.")

    st.subheader("Monitoring Concepts")

    st.markdown("""
    1. Observe security events.
    2. Evaluate suspicious activity.
    3. Calculate risk levels.
    4. Apply access policies.
    5. Record security decisions.
    """)

# --------------------------------------------------
# REPORTS AND AUDIT LOGS
# --------------------------------------------------

elif page == "Reports & Audit Logs":

    st.title("📊 Reports & Security Audit Logs")

    st.write("Review recorded Zero-Trust access decisions.")

    try:
        logs = get_access_logs(limit=500)

        if logs:
            df = pd.DataFrame(logs)

            st.dataframe(df, use_container_width=True)

            csv_data = df.to_csv(index=False).encode("utf-8")

            st.download_button(
                "Download Audit Logs CSV",
                data=csv_data,
                file_name="resinet_idam_audit_logs.csv",
                mime="text/csv"
            )

            st.metric("Total Displayed Audit Records", len(df))

        else:
            st.info("No audit records are available yet.")

    except Exception as error:
        st.error(f"Unable to load audit logs: {error}")

    st.subheader("Report Information")
    st.write("Reports are based on recorded access-evaluation events.")
