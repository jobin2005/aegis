# 🛡️ Aegis Hybrid IDS

Aegis is a modern, dual-engine Intrusion Detection System (IDS) that combines **high-speed signature matching** (mimicking Snort) with deep-inspection **AI Anomaly Detection** (Isolation Forest) to detect zero-day exploits. It features a stunning, real-time glassmorphism dashboard built with FastAPI.

## ✨ Features
- **Dual Threat Engine**: Regex fast-path for known vulnerabilities (SQLi, Log4j, Nmap).
- **Machine Learning**: Scikit-Learn Isolation Forest trained on *live* biological network data to detect behavioral deviations.
- **Stand-alone or Cloud**: Seamlessly logs to local SQLite or remote hosting (Supabase).
- **Live Response Dashboard**: Beautiful FastAPI-powered minimalist UI with immediate threat visualization.

## 🚀 Setup & Installation

**1. Clone and Install Dependencies**
```bash
git clone https://github.com/yourusername/aegis-ids.git
cd aegis-ids
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**2. Configure the Network Interface**
Create a `.env` file and set the interface to monitor (e.g., `lo`, `eth0`, or `wlan0`).
```env
SNIFF_INTERFACE=lo
```

## 🧠 Training the AI Model
Since Aegis relies on detecting anomalies to catch unknown threats, you must train the AI on your unique network traffic before starting the IDS.
```bash
sudo $(which python3) scripts/train_live_model.py
```
*(Browse the web normally for 45-60 seconds while Aegis builds a secure baseline of your "normal" behavior).*

## 🛑 Starting the Sentinel 
First, spin up your Threat Engine:
```bash
sudo $(which python3) main.py
```

Next, in a separate terminal window, launch the User Interface:
```bash
source venv/bin/activate
python3 src/ui/app.py
```
You can view the real-time analytics dashboard by opening `http://127.0.0.1:8000` in your web browser!

## 🎯 Testing High Alerts
Want to see the system catch a cyber attack in real-time? Open a totally new terminal and shoot a raw malicious payload at it via Netcat:
```bash
echo "UNION SELECT 1" | nc -u -w 1 127.0.0.1 80
```
Watch the Dashboard instantly flash red with a **HIGH Severity SQL Injection Alert** before the packet even finishes downloading!
