"""SentinelNet SOC dashboard."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st
from streamlit_autorefresh import st_autorefresh

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ALERT_FILE = PROJECT_ROOT / "alerts" / "alerts.csv"
REQUIRED_COLUMNS = {"Timestamp", "SourceIP", "Port", "Service", "Severity"}
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
SEVERITY_COLORS = {
    "Critical": "#ff3b5c",
    "High": "#ff8a3d",
    "Medium": "#f4c95d",
    "Low": "#3ddc97",
}
RISK_WEIGHTS = {"Critical": 100, "High": 65, "Medium": 35, "Low": 10}

st.set_page_config(
    page_title="SentinelNet | SOC Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .block-container {padding-top: 2rem; padding-bottom: 3rem;}
    [data-testid="stMetric"] {
        background: linear-gradient(135deg, rgba(21, 30, 48, .95), rgba(13, 20, 34, .95));
        border: 1px solid rgba(108, 140, 255, .22);
        border-radius: 14px;
        padding: 16px;
    }
    [data-testid="stMetricValue"] {color: #e8eeff;}
    .status-pill {
        display: inline-block;
        padding: .3rem .65rem;
        border-radius: 999px;
        background: rgba(61, 220, 151, .12);
        color: #3ddc97;
        border: 1px solid rgba(61, 220, 151, .28);
        font-size: .8rem;
        font-weight: 700;
        letter-spacing: .04em;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def load_alerts(path: Path) -> pd.DataFrame:
    """Load and normalize alert data without caching stale capture results."""

    if not path.exists() or path.stat().st_size == 0:
        return pd.DataFrame()

    frame = pd.read_csv(path)
    missing = REQUIRED_COLUMNS.difference(frame.columns)
    if missing:
        raise ValueError(f"Alert file is missing columns: {', '.join(sorted(missing))}")

    frame["Timestamp"] = pd.to_datetime(frame["Timestamp"], errors="coerce", utc=True)
    frame["Port"] = pd.to_numeric(frame["Port"], errors="coerce").astype("Int64")
    frame["Severity"] = frame["Severity"].astype(str).str.title()
    return frame.dropna(subset=["Timestamp", "SourceIP", "Severity"])


def calculate_risk_score(frame: pd.DataFrame) -> int:
    """Return a transparent 0-100 score based on the filtered severity mix."""

    if frame.empty:
        return 0
    weights = frame["Severity"].map(RISK_WEIGHTS).fillna(0)
    return round(float(weights.mean()))


def apply_time_window(frame: pd.DataFrame, window: str) -> pd.DataFrame:
    if frame.empty or window == "All data":
        return frame

    durations = {
        "Last hour": pd.Timedelta(hours=1),
        "Last 24 hours": pd.Timedelta(hours=24),
        "Last 7 days": pd.Timedelta(days=7),
    }
    newest = frame["Timestamp"].max()
    return frame[frame["Timestamp"] >= newest - durations[window]]


def empty_state() -> None:
    st.info("No alert data is available yet. Generate safe demo data or start packet capture.")
    st.code("python scripts/generate_demo_data.py\nstreamlit run dashboard/dashboard.py")


with st.sidebar:
    st.header("Console controls")
    refresh_seconds = st.select_slider(
        "Refresh interval",
        options=[5, 10, 30, 60],
        value=10,
        format_func=lambda value: f"{value} seconds",
    )
    st_autorefresh(interval=refresh_seconds * 1000, key="sentinelnet-refresh")
    time_window = st.selectbox(
        "Analysis window",
        ["All data", "Last hour", "Last 24 hours", "Last 7 days"],
    )
    st.caption("Port-based rules are triage signals and require analyst validation.")

st.markdown('<span class="status-pill">● MONITORING CONSOLE</span>', unsafe_allow_html=True)
st.title("SentinelNet Security Operations Center")
st.caption("Explainable network detections · analyst-first triage · live CSV telemetry")

try:
    alerts = load_alerts(ALERT_FILE)
except (OSError, ValueError, pd.errors.ParserError) as exc:
    st.error(f"Unable to load alert telemetry: {exc}")
    st.stop()

if alerts.empty:
    empty_state()
    st.stop()

alerts = apply_time_window(alerts, time_window)
available_severities = [item for item in SEVERITY_ORDER if item in alerts["Severity"].unique()]

with st.sidebar:
    severities = st.multiselect(
        "Severity",
        options=available_severities,
        default=available_severities,
    )
    source_query = st.text_input("Source IP contains", placeholder="203.0.113")

filtered = alerts[alerts["Severity"].isin(severities)]
if source_query:
    filtered = filtered[filtered["SourceIP"].astype(str).str.contains(source_query, case=False)]

if filtered.empty:
    st.warning("No alerts match the selected filters.")
    st.stop()

severity_counts = filtered["Severity"].value_counts()
critical = int(severity_counts.get("Critical", 0))
high = int(severity_counts.get("High", 0))
risk_score = calculate_risk_score(filtered)
unique_sources = int(filtered["SourceIP"].nunique())

metric_columns = st.columns(5)
metric_columns[0].metric("Filtered alerts", f"{len(filtered):,}")
metric_columns[1].metric("Critical", critical)
metric_columns[2].metric("High", high)
metric_columns[3].metric("Unique sources", unique_sources)
metric_columns[4].metric("Severity risk", f"{risk_score}/100")

st.caption(
    "Severity risk is the mean filtered alert weight: Critical 100, High 65, "
    "Medium 35, Low 10. It is not a host vulnerability score."
)

left_chart, right_chart = st.columns(2)
with left_chart:
    ordered_counts = severity_counts.reindex(SEVERITY_ORDER, fill_value=0).reset_index()
    ordered_counts.columns = ["Severity", "Alerts"]
    severity_chart = px.bar(
        ordered_counts,
        x="Severity",
        y="Alerts",
        color="Severity",
        color_discrete_map=SEVERITY_COLORS,
        title="Alert severity distribution",
        template="plotly_dark",
    )
    severity_chart.update_layout(showlegend=False, margin=dict(l=10, r=10, t=50, b=10))
    st.plotly_chart(severity_chart, width="stretch")

with right_chart:
    service_counts = filtered["Service"].value_counts().head(8).sort_values().reset_index()
    service_counts.columns = ["Service", "Alerts"]
    service_chart = px.bar(
        service_counts,
        x="Alerts",
        y="Service",
        orientation="h",
        title="Most frequent detection services",
        template="plotly_dark",
        color="Alerts",
        color_continuous_scale="Bluered",
    )
    service_chart.update_layout(
        coloraxis_showscale=False,
        margin=dict(l=10, r=10, t=50, b=10),
    )
    st.plotly_chart(service_chart, width="stretch")

timeline = filtered.set_index("Timestamp").resample("15min").size().rename("Alerts").reset_index()
timeline_chart = px.area(
    timeline,
    x="Timestamp",
    y="Alerts",
    title="Detection activity over time (15-minute buckets)",
    template="plotly_dark",
    color_discrete_sequence=["#6c8cff"],
)
timeline_chart.update_layout(margin=dict(l=10, r=10, t=50, b=10))
st.plotly_chart(timeline_chart, width="stretch")

st.subheader("Priority queue")
priority = filtered.copy()
priority["_priority"] = priority["Severity"].map(RISK_WEIGHTS).fillna(0)
priority = priority.sort_values(["_priority", "Timestamp"], ascending=[False, False]).drop(
    columns="_priority"
)
display_columns = [
    column
    for column in (
        "Timestamp",
        "Severity",
        "SourceIP",
        "DestinationIP",
        "Protocol",
        "Port",
        "Service",
        "Category",
        "Description",
    )
    if column in priority.columns
]
st.dataframe(
    priority[display_columns],
    width="stretch",
    hide_index=True,
    column_config={
        "Timestamp": st.column_config.DatetimeColumn(
            "Detected (UTC)", format="YYYY-MM-DD HH:mm:ss"
        ),
        "Port": st.column_config.NumberColumn("Port", format="%d"),
    },
)

download_data = priority[display_columns].to_csv(index=False).encode("utf-8")
st.download_button(
    "Export filtered alerts",
    data=download_data,
    file_name="sentinelnet-alert-export.csv",
    mime="text/csv",
)

with st.expander("Detection scope and limitations"):
    st.markdown(
        """
        - SentinelNet stores packet metadata only; it does not retain packet payloads.
        - A suspicious destination port is an explainable triage signal, not proof of compromise.
        - Port-scan alerts use a rolling unique-port threshold with a cooldown to limit duplicates.
        - Production deployments should add authentication, durable storage,
          enrichment, and SIEM export.
        """
    )

st.divider()
st.caption("SentinelNet · Built by Darshnoor Kaur · Defensive security learning project")
