import pandas as pd
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)
from reportlab.lib.styles import getSampleStyleSheet

# ======================================
# LOAD ALERT DATA
# ======================================

df = pd.read_csv("alerts/alerts.csv")

critical = len(df[df["Severity"] == "Critical"])
high = len(df[df["Severity"] == "High"])
medium = len(df[df["Severity"] == "Medium"])

total_alerts = len(df)

security_score = max(
    0,
    100 - (critical * 25 + high * 10 + medium * 5)
)

# ======================================
# CREATE PDF
# ======================================

pdf = SimpleDocTemplate(
    "reports/SentinelNet_Report.pdf"
)

styles = getSampleStyleSheet()

content = []

# ======================================
# TITLE
# ======================================

content.append(
    Paragraph(
        "SentinelNet Security Incident Report",
        styles["Title"]
    )
)

content.append(Spacer(1, 20))

# ======================================
# SUMMARY
# ======================================

content.append(
    Paragraph(
        f"Total Alerts: {total_alerts}",
        styles["Normal"]
    )
)

content.append(
    Paragraph(
        f"Critical Alerts: {critical}",
        styles["Normal"]
    )
)

content.append(
    Paragraph(
        f"High Alerts: {high}",
        styles["Normal"]
    )
)

content.append(
    Paragraph(
        f"Medium Alerts: {medium}",
        styles["Normal"]
    )
)

content.append(
    Paragraph(
        f"Security Score: {security_score}/100",
        styles["Normal"]
    )
)

content.append(Spacer(1, 20))

# ======================================
# CRITICAL THREATS
# ======================================

content.append(
    Paragraph(
        "Critical Threats Detected",
        styles["Heading2"]
    )
)

critical_df = df[df["Severity"] == "Critical"]

if critical_df.empty:

    content.append(
        Paragraph(
            "No critical threats detected.",
            styles["Normal"]
        )
    )

else:

    for _, row in critical_df.iterrows():

        content.append(
            Paragraph(
                f"Port {row['Port']} | "
                f"{row['Service']} | "
                f"{row['Severity']}",
                styles["Normal"]
            )
        )

content.append(Spacer(1, 20))

# ======================================
# RECOMMENDATIONS
# ======================================

content.append(
    Paragraph(
        "Recommendations",
        styles["Heading2"]
    )
)

content.append(
    Paragraph(
        "- Investigate all critical alerts immediately.",
        styles["Normal"]
    )
)

content.append(
    Paragraph(
        "- Block suspicious ports if not required.",
        styles["Normal"]
    )
)

content.append(
    Paragraph(
        "- Monitor network traffic continuously.",
        styles["Normal"]
    )
)

content.append(
    Paragraph(
        "- Review firewall and IDS configurations.",
        styles["Normal"]
    )
)

# ======================================
# BUILD PDF
# ======================================

pdf.build(content)

print("Report Generated Successfully!")