
import pandas as pd
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    PageBreak,
    Table,
    TableStyle
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

# ==========================================
# LOAD ALERT DATA
# ==========================================

df = pd.read_csv("alerts/alerts.csv")

critical = len(df[df["Severity"] == "Critical"])
high = len(df[df["Severity"] == "High"])
medium = len(df[df["Severity"] == "Medium"])

total_alerts = len(df)

# Improved demo security score
security_score = max(
    0,
    int(100 - (critical * 2 + high * 1 + medium * 0.5))
)

# ==========================================
# PDF SETUP
# ==========================================

pdf = SimpleDocTemplate(
    "reports/SentinelNet_Report.pdf"
)

styles = getSampleStyleSheet()
content = []

# ==========================================
# COVER PAGE
# ==========================================

content.append(
    Paragraph(
        "SentinelNet Security Operations Center",
        styles["Title"]
    )
)

content.append(Spacer(1, 20))

content.append(
    Paragraph(
        "Threat Detection & Monitoring Report",
        styles["Heading1"]
    )
)

content.append(Spacer(1, 30))

content.append(
    Paragraph(
        "Prepared By: Darshnoor Kaur",
        styles["Normal"]
    )
)

content.append(
    Paragraph(
        "Cybersecurity Monitoring Platform",
        styles["Normal"]
    )
)

content.append(
    Paragraph(
        "Version: 1.0",
        styles["Normal"]
    )
)

content.append(
    Paragraph(
        "Year: 2026",
        styles["Normal"]
    )
)

content.append(PageBreak())

# ==========================================
# EXECUTIVE SUMMARY
# ==========================================

content.append(
    Paragraph(
        "Executive Summary",
        styles["Heading1"]
    )
)

summary = """
SentinelNet is a Security Operations Center (SOC)
monitoring platform developed for real-time network
traffic inspection, threat detection, alert management,
analytics visualization, and incident reporting.

The platform continuously monitors suspicious network
activity and generates alerts categorized into Critical,
High, and Medium severity levels.

This report summarizes the threats detected during
the monitoring period and provides recommendations
for improving security posture.
"""

content.append(
    Paragraph(summary, styles["BodyText"])
)

content.append(PageBreak())

# ==========================================
# THREAT STATISTICS
# ==========================================

content.append(
    Paragraph(
        "Threat Statistics",
        styles["Heading1"]
    )
)

table_data = [
    ["Metric", "Value"],
    ["Total Alerts", str(total_alerts)],
    ["Critical Alerts", str(critical)],
    ["High Alerts", str(high)],
    ["Medium Alerts", str(medium)],
    ["Security Score", f"{security_score}/100"]
]

table = Table(table_data, colWidths=[220, 150])

table.setStyle(
    TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("GRID", (0, 0), (-1, -1), 1, colors.black),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")
    ])
)

content.append(table)

content.append(Spacer(1, 20))

content.append(
    Paragraph(
        f"""
        Total alerts detected: {total_alerts}.
        Critical alerts represent the highest-risk
        security events and require immediate
        investigation.
        """,
        styles["BodyText"]
    )
)

content.append(PageBreak())

# ==========================================
# TOP THREATS
# ==========================================

content.append(
    Paragraph(
        "Top Threats Detected",
        styles["Heading1"]
    )
)

top_threats = (
    df.groupby(["Port", "Service", "Severity"])
    .size()
    .reset_index(name="Count")
    .sort_values("Count", ascending=False)
    .head(10)
)

table_data = [["Port", "Service", "Severity", "Count"]]

for _, row in top_threats.iterrows():
    table_data.append([
        str(row["Port"]),
        str(row["Service"]),
        str(row["Severity"]),
        str(row["Count"])
    ])

table = Table(table_data)

table.setStyle(
    TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("GRID", (0, 0), (-1, -1), 1, colors.black)
    ])
)

content.append(table)

content.append(PageBreak())

# ==========================================
# CRITICAL THREAT ANALYSIS
# ==========================================

content.append(
    Paragraph(
        "Critical Threat Analysis",
        styles["Heading1"]
    )
)

content.append(
    Paragraph(
        """
        Critical alerts indicate potentially dangerous
        services, suspicious communication patterns,
        or ports commonly associated with exploitation
        frameworks and unauthorized access attempts.

        Ports such as Telnet (23), SMB (445),
        RDP (3389), and Metasploit-related services
        should be closely monitored and restricted
        where possible.
        """,
        styles["BodyText"]
    )
)

content.append(PageBreak())

# ==========================================
# RECOMMENDATIONS
# ==========================================

content.append(
    Paragraph(
        "Security Recommendations",
        styles["Heading1"]
    )
)

recommendations = [
    "Investigate all Critical alerts immediately.",
    "Disable unnecessary services and ports.",
    "Implement firewall-based traffic filtering.",
    "Enable continuous network monitoring.",
    "Deploy IDS/IPS solutions.",
    "Perform regular vulnerability assessments.",
    "Apply operating system and software patches.",
    "Restrict remote administration services."
]

for item in recommendations:
    content.append(
        Paragraph(
            f"• {item}",
            styles["BodyText"]
        )
    )

content.append(PageBreak())

# ==========================================
# CONCLUSION
# ==========================================

content.append(
    Paragraph(
        "Conclusion",
        styles["Heading1"]
    )
)

content.append(
    Paragraph(
        """
        SentinelNet successfully demonstrated
        real-time threat monitoring, alert generation,
        incident analysis, and security reporting.

        The platform provides security analysts with
        actionable insights through threat analytics,
        incident reports, and dashboard visualization.

        Future enhancements may include machine
        learning-based anomaly detection, automated
        threat intelligence feeds, and cloud-based
        deployment.
        """,
        styles["BodyText"]
    )
)

# ==========================================
# BUILD REPORT
# ==========================================

pdf.build(content)

print("Professional SentinelNet Report Generated Successfully!")
