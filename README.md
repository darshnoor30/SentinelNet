# SentinelNet

## Overview

SentinelNet is a SOC-inspired cybersecurity monitoring platform built using Python. It captures network traffic, detects suspicious activities, generates alerts, performs threat analytics, and visualizes security incidents through an interactive dashboard.

---

## Features

- Real-Time Packet Capture
- Threat Detection Engine
- Suspicious Port Monitoring
- Alert Logging
- Security Analytics
- Threat Intelligence Summary
- Interactive SOC Dashboard
- PDF Incident Reporting

---

## Technologies Used

- Python
- Scapy
- Pandas
- Streamlit
- Plotly
- ReportLab

---

## Architecture

![Architecture](architecture.png)

---

## Dashboard Preview

### Main Dashboard

![Dashboard](screenshots/dashboard_main.png)

### Threat Analytics

![Analytics](screenshots/dashboard_analytics.png)

### Threat Timeline & Intelligence

![Timeline](screenshots/dashboard_timeline.png)

---

## Project Structure

```text
SentinelNet
├── alerts
├── analytics
├── dashboard
├── detection_engine
├── logs
├── packet_capture
├── reports
├── screenshots
└── README.md
```

---

## Installation

```bash
pip install -r requirements.txt
```

---

## Run Packet Capture

```bash
python packet_capture/capture.py
```

---

## Run Dashboard

```bash
streamlit run dashboard/dashboard.py
```

---

## Future Enhancements

- Machine Learning Threat Detection
- Threat Intelligence Integration
- Email Alerting System
- Automated Incident Response

---

## Developer

Darshnoor Kaur

B.Tech CSE (Cybersecurity)