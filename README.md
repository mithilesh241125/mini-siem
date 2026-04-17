🔐 Mini SIEM Dashboard

A lightweight Security Information and Event Management (SIEM) system that analyzes log data to detect suspicious activities, correlate attack patterns, and visualize security events in real time.

---

🚀 Overview

This project simulates a basic Security Operations Center (SOC) by processing system logs and identifying potential security threats such as brute force attacks, sensitive file access, and anomalous user behavior.

It combines rule-based detection, risk scoring, and visualization to provide meaningful insights from raw log data.

---

🔍 Features

- 🔐 Detects brute force login attempts
- 📁 Identifies sensitive file access
- 🌐 Flags unknown or suspicious IP activity
- 🔗 Correlates multi-step attacks
- 📊 Assigns risk scores to IPs
- ⚡ Real-time dashboard with alerts
- 🧠 Attack timeline visualization

---

🧠 How It Works

Logs → Parsing → Detection Rules → Alerts → Risk Scoring → Dashboard

1. Log data is ingested from a structured dataset
2. Detection rules analyze patterns (e.g., repeated login failures)
3. Alerts are generated with severity levels
4. Events are correlated to identify multi-stage attacks
5. Risk scores are assigned based on behavior
6. Results are displayed in a real-time dashboard

---

📊 Dashboard Preview

(Add screenshots here)

- Alert categories (High / Medium / Low)
- Real-time log monitoring
- Attack timeline per IP
- Risk score indicators

---

⚙️ Installation

git clone https://github.com/mithilesh241125/mini-siem
cd mini-siem
pip install -r requirements.txt
python app.py

---

🛠️ Technologies Used

- Python
- Flask
- Log Analysis
- Security Monitoring
- Data Processing

---

📂 Project Structure

mini-siem/
│
├── app.py
├── detector.py
├── logs.csv
├── templates/
├── static/
├── requirements.txt
└── README.md

---

🎯 Use Case

This project demonstrates how security teams monitor logs, detect threats, and analyze attack patterns in real-world environments.

It is designed as a beginner-friendly simulation of a SIEM system used in Security Operations Centers (SOC).

---

🚀 Future Improvements

- Real-time log streaming
- Integration with external log sources
- Advanced anomaly detection using ML
- User authentication system
- Alert notifications (email/SMS)

---

📌 Author

Mithilesh R
🔗 https://github.com/mithilesh241125

---