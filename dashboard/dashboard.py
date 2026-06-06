import streamlit as st
import pandas as pd
import plotly.express as px
import os
from streamlit_autorefresh import st_autorefresh


# =====================================================
# PAGE CONFIG
# =====================================================

st.set_page_config(
    page_title="SentinelNet SOC Dashboard",
    page_icon="🛡",
    layout="wide"
)
st_autorefresh(
    interval=5000,
    key="sentinel_refresh"
)

st.title("🛡 SentinelNet Security Operations Center")

st.caption(
    "Real-Time Network Threat Detection, Analysis and Incident Monitoring Platform"
)

# =====================================================
# LOAD ALERT DATA
# =====================================================

ALERT_FILE = "alerts/alerts.csv"

if not os.path.exists(ALERT_FILE):
    st.error("alerts.csv not found.")
    st.stop()

df = pd.read_csv(ALERT_FILE)

if df.empty:
    st.warning("No alerts detected yet.")
    st.stop()

# =====================================================
# SECURITY METRICS
# =====================================================

critical = len(df[df["Severity"] == "Critical"])
high = len(df[df["Severity"] == "High"])
medium = len(df[df["Severity"] == "Medium"])

security_score = 100
security_score -= (critical * 20)
security_score -= (high * 10)
security_score -= (medium * 5)

security_score = max(security_score, 20)

col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("Total Alerts", len(df))
col2.metric("Critical", critical)
col3.metric("High", high)
col4.metric("Medium", medium)
col5.metric("Security Score", f"{security_score}/100")

st.divider()

# =====================================================
# ALERT TABLE
# =====================================================

st.subheader("📋 Threat Alert Log")

st.dataframe(
    df,
    use_container_width=True
)

st.divider()

# =====================================================
# SEVERITY DISTRIBUTION
# =====================================================

st.subheader("📊 Threat Severity Distribution")

severity_counts = df["Severity"].value_counts()

fig_pie = px.pie(
    values=severity_counts.values,
    names=severity_counts.index,
    title="Threat Severity Breakdown"
)

st.plotly_chart(
    fig_pie,
    use_container_width=True
)

st.divider()

# =====================================================
# TOP ATTACKING IPS
# =====================================================

st.subheader("🌍 Top Attacking IPs")

if "SourceIP" in df.columns:

    ip_counts = df["SourceIP"].value_counts()

    fig_ips = px.bar(
        x=ip_counts.index,
        y=ip_counts.values,
        labels={
            "x": "Source IP",
            "y": "Alert Count"
        },
        title="Most Active Threat Sources"
    )

    st.plotly_chart(
        fig_ips,
        use_container_width=True
    )

else:
    st.info("Source IP data not available")

st.divider()

# =====================================================
# TOP THREAT PORTS
# =====================================================

st.subheader("🎯 Top Threat Ports")

if "Port" in df.columns:

    port_counts = df["Port"].value_counts()

    fig_ports = px.bar(
        x=port_counts.index,
        y=port_counts.values,
        labels={
            "x": "Port",
            "y": "Occurrences"
        },
        title="Most Frequently Triggered Threat Ports"
    )

    st.plotly_chart(
        fig_ports,
        use_container_width=True
    )

st.divider()

# =====================================================
# CRITICAL ALERTS
# =====================================================

st.subheader("🚨 Critical Threats")

critical_df = df[df["Severity"] == "Critical"]

if critical_df.empty:
    st.success("No Critical Threats Detected")
else:
    st.dataframe(
        critical_df,
        use_container_width=True
    )

st.divider()

# =====================================================
# ATTACK TIMELINE
# =====================================================

st.subheader("📈 Threat Activity Timeline")

if "Timestamp" in df.columns:

    try:

        df["Timestamp"] = pd.to_datetime(df["Timestamp"])

        timeline = (
    df.groupby(
        df["Timestamp"].dt.strftime("%H:%M")
    ).size()
)

        fig_time = px.line(
            x=timeline.index,
            y=timeline.values,
            labels={
                "x": "Hour",
                "y": "Threat Count"
            },
            title="Threat Activity Over Time"
        )

        st.plotly_chart(
            fig_time,
            use_container_width=True
        )

    except Exception:
        st.info("Unable to generate timeline.")

else:
    st.info("Timestamp data not available.")

st.divider()

# =====================================================
# THREAT SUMMARY
# =====================================================

st.subheader("🧠 Threat Intelligence Summary")

if "Port" in df.columns and not df["Port"].empty:
    most_common_port = df["Port"].mode()[0]
else:
    most_common_port = "N/A"

if "Severity" in df.columns and not df["Severity"].empty:
    most_common_severity = df["Severity"].mode()[0]
else:
    most_common_severity = "Unknown"

port_mapping = {
    21: "FTP",
    23: "Telnet",
    445: "SMB",
    3389: "RDP",
    4444: "Metasploit",
    1337: "Backdoor Activity"
}

service_name = port_mapping.get(most_common_port, "Unknown")

st.info(
    f"""
    Most targeted service was **{service_name} (Port {most_common_port})**.

    Most frequent threat severity was **{most_common_severity}**.

    Security analysts should prioritize investigation of recurring high-risk activities.
    """
)

if "SourceIP" in df.columns:
    top_ip = df["SourceIP"].value_counts().idxmax()
    st.warning(f"Most active source IP detected: **{top_ip}**")

# =====================================================
# FOOTER
# =====================================================

st.markdown("---")
st.caption(
    "SOC-Inspired Real-Time Network Threat Detection, Security Analytics and Incident Monitoring Platform"
)