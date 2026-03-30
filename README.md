# 🛡️ Advanced Network Traffic Analyzer

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/Flask-2.3+-green.svg)](https://flask.palletsprojects.com/)
[![Scikit-Learn](https://img.shields.io/badge/ML-Scikit--learn-orange.svg)](https://scikit-learn.org/)
[![Status](https://img.shields.io/badge/Status-Complete-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-MIT-purple.svg)]()

A comprehensive, **Machine Learning-powered** Network Traffic Analysis system designed for deep packet inspection (DPI), anomaly detection, and real-time security monitoring. This system provides a robust web interface to visualize complex network patterns and identify potential threats with high precision.

---

## 🚀 Key Modules & Features

| Feature | Description |
| :--- | :--- |
| **🔍 Deep Packet Inspection** | Full support for **PCAP, PCAPNG, and CSV** file formats with automated schema detection. |
| **🤖 ML Anomaly Detection** | Uses **Isolation Forest** and **One-Class SVM** to identify stealthy network intrusions. |
| **📊 Interactive Visualizations** | Real-time charts for protocol distribution, traffic timelines, and correlation heatmaps. |
| **📄 Professional Reporting** | Export comprehensive analysis results to **PDF (with charts)**, **JSON**, or **CSV**. |
| **⚡ High Performance** | Optimized processing for large datasets (up to **10GB**) with intelligent sampling. |
| **📡 Real-time Monitoring** | Dynamic dashboard to track network status and receive immediate threat alerts. |

---

## 🛠️ Project Architecture

The system is built with a modular approach, separating data parsing, machine learning, and visualization:

1.  **Backend (Flask)**: RESTful API for handling massive file uploads and orchestration.
2.  **ML Engine (Scikit-learn)**: Unsupervised learning models for threat identification.
3.  **DPI Engine (Scapy/PyShark)**: Low-level packet parsing and feature extraction.
4.  **UI (Bootstrap 5 & Chart.js)**: A sleek, responsive dashboard for end-users.

---

## 📥 Installation

Navigate to the project directory and follow these steps:

### 1. Prerequisite
Ensure you have Python 3.8+ installed. You may also need `WinPcap` or `Npcap` if you're running on Windows for live packet capture.

### 2. Automated Setup (Recommended)
This script will create a virtual environment and install all necessary dependencies:
```bash
cd Network_Traffic_Analyser-main
python startup_script.py
```

### 3. Manual Installation
Alternatively, install dependencies via `pip`:
```bash
cd Network_Traffic_Analyser-main
pip install -r requirements.txt
python app.py
```

---

## 🖥️ Usage Guide

1.  **Launch the App**: Run `python app.py` and navigate to `http://localhost:5000` in your browser.
2.  **Upload Data**: 
    - Go to the **Upload** tab.
    - Drag & Drop a **PCAP** or **CSV** file.
    - Click **Start Analysis**.
3.  **View Dashboard**:
    - **Overview**: High-level stats (Packet count, throughput).
    - **Visuals**: Protocol pie charts and traffic timelines.
    - **Anomalies**: Detailed list of suspicious activity detected by ML.
4.  **Export Results**:
    - Navigate to the **Reports** tab to download your customized PDF report.

---

## 📋 Technological Stack

- **Languages**: Python, JavaScript, CSS3, HTML5
- **Frameworks**: Flask (Backend), Bootstrap 5 (UI)
- **Data Engineering**: Pandas, NumPy
- **Machine Learning**: Scikit-Learn, Joblib
- **Visualization**: Matplotlib, Seaborn, Plotly, Chart.js
- **Network Stack**: Scapy, PyShark, psutil
- **Reporting**: ReportLab, WeasyPrint, Pillow

---

## 🛡️ Security & Optimization

- **Validated Uploads**: File signatures and extensions are strictly checked.
- **Large File Support**: Chunks data into 50k rows for memory efficiency.
- **Cleanups**: Temporary session data is scrubbed automatically.

---

## 🤝 Support & Contribution

If you encounter any issues:
1.  Check the **Troubleshooting** section in the subfolder.
2.  Ensure all optional dependencies for enhanced PCAP features are installed.
3.  Verify that your hardware supports the memory-intensive ML training for very large datasets.

**Developed with ❤️ by [Your Name/GitHub Profile]**
