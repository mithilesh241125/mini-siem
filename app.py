from datetime import datetime, timedelta

from flask import Flask, render_template_string
from detector import analyze_logs, load_logs

# Create the Flask application.
app = Flask(__name__)


@app.route("/")
def dashboard():
    # Current time is shown on the dashboard and used for "NEW" alert badges.
    now = datetime.now()

    # Read log data from the text file.
    logs = load_logs("logs.txt")

    # Run the detector and collect all dashboard data.
    analysis = analyze_logs(logs)
    alerts = analysis["alerts"]
    timeline = analysis["timeline"]

    # Mark very recent alerts so they stand out in the dashboard.
    for alert in alerts:
        alert_time = alert.get("alert_time")
        alert["is_new"] = bool(
            alert_time and now - alert_time <= timedelta(minutes=2)
        )
        alert["alert_time_text"] = (
            alert_time.strftime("%Y-%m-%d %H:%M:%S") if alert_time else "Calculated rule"
        )

    # Small helper numbers for the summary cards.
    high_count = sum(1 for alert in alerts if alert["severity"] == "HIGH")
    medium_count = sum(1 for alert in alerts if alert["severity"] == "MEDIUM")
    low_count = sum(1 for alert in alerts if alert["severity"] == "LOW")
    last_updated = now.strftime("%Y-%m-%d %H:%M:%S")

    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta http-equiv="refresh" content="5">
        <title>Mini SIEM Dashboard</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 0;
                background: linear-gradient(180deg, #e9f1ff 0%, #f8fafc 100%);
                color: #0f172a;
            }

            .container {
                max-width: 1150px;
                margin: 0 auto;
                padding: 24px;
            }

            .header {
                background: linear-gradient(135deg, #081226 0%, #0f172a 60%, #172554 100%);
                color: #ffffff;
                padding: 24px;
                border-radius: 16px;
                margin-bottom: 20px;
                box-shadow: 0 12px 30px rgba(15, 23, 42, 0.18);
                display: flex;
                justify-content: space-between;
                gap: 16px;
                align-items: end;
                flex-wrap: wrap;
            }

            .header h1 {
                margin: 0 0 8px 0;
            }

            .header-status {
                min-width: 240px;
                padding: 14px 16px;
                border-radius: 12px;
                background: rgba(255, 255, 255, 0.08);
                border: 1px solid rgba(255, 255, 255, 0.14);
            }

            .header-status p {
                margin: 4px 0;
                font-size: 14px;
            }

            .summary-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                gap: 16px;
                margin-bottom: 20px;
            }

            .summary-card,
            .card {
                background: #ffffff;
                border-radius: 16px;
                padding: 20px;
                box-shadow: 0 10px 25px rgba(15, 23, 42, 0.08);
            }

            .summary-card {
                position: relative;
                overflow: hidden;
                border: 1px solid #dbe4f0;
            }

            .summary-card::before {
                content: "";
                position: absolute;
                inset: 0 auto 0 0;
                width: 6px;
                background: #94a3b8;
            }

            .summary-card.total::before {
                background: #334155;
            }

            .summary-card.high::before {
                background: #dc2626;
            }

            .summary-card.medium::before {
                background: #d97706;
            }

            .summary-card.low::before {
                background: #2563eb;
            }

            .summary-card h3,
            .card h2,
            .timeline-card h3 {
                margin-top: 0;
            }

            .summary-number {
                margin: 0;
                font-size: 32px;
                font-weight: 800;
            }

            .summary-label {
                margin: 0;
                color: #475569;
                font-size: 14px;
            }

            .layout {
                display: grid;
                grid-template-columns: 1.2fr 0.8fr;
                gap: 20px;
                margin-bottom: 20px;
            }

            .alert-list {
                display: grid;
                gap: 12px;
            }

            .alert {
                border-left: 8px solid #94a3b8;
                border-radius: 12px;
                padding: 14px 16px;
                background: #f8fafc;
                border: 1px solid #dbe4f0;
            }

            .alert-high {
                background: linear-gradient(135deg, #fff1f2 0%, #fee2e2 100%);
                border-left-color: #dc2626;
                box-shadow: 0 0 0 1px rgba(220, 38, 38, 0.12), 0 0 18px rgba(220, 38, 38, 0.14);
                animation: highPulse 1.8s infinite;
            }

            .alert-medium {
                background: #fef3c7;
                border-left-color: #d97706;
            }

            .alert-low {
                background: #dbeafe;
                border-left-color: #2563eb;
            }

            .alert-top {
                display: flex;
                justify-content: space-between;
                gap: 12px;
                align-items: center;
                margin-bottom: 8px;
                flex-wrap: wrap;
            }

            .alert-meta {
                font-size: 13px;
                color: #334155;
                font-weight: bold;
            }

            .alert-message {
                line-height: 1.5;
            }

            .badge-row {
                display: flex;
                gap: 8px;
                align-items: center;
                flex-wrap: wrap;
            }

            .badge {
                display: inline-block;
                padding: 4px 10px;
                border-radius: 999px;
                font-size: 12px;
                font-weight: 700;
                letter-spacing: 0.03em;
            }

            .badge-severity-high {
                background: #dc2626;
                color: white;
            }

            .badge-severity-medium {
                background: #f59e0b;
                color: white;
            }

            .badge-severity-low {
                background: #2563eb;
                color: white;
            }

            .badge-new {
                background: #10b981;
                color: white;
                box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.14);
            }

            .alert-new {
                outline: 2px solid rgba(16, 185, 129, 0.4);
            }

            .safe {
                background: #dcfce7;
                border-left: 6px solid #16a34a;
                padding: 14px;
                border-radius: 12px;
            }

            .timeline-grid {
                display: grid;
                gap: 16px;
            }

            .timeline-card {
                background: #ffffff;
                border-radius: 16px;
                padding: 18px;
                box-shadow: 0 10px 25px rgba(15, 23, 42, 0.08);
                border-top: 5px solid #cbd5e1;
            }

            .timeline-card.untrusted {
                border-top-color: #ef4444;
            }

            .timeline-card.trusted {
                border-top-color: #22c55e;
            }

            .timeline-event {
                margin-bottom: 10px;
                padding-bottom: 10px;
                border-bottom: 1px solid #e2e8f0;
            }

            .timeline-event:last-child {
                margin-bottom: 0;
                padding-bottom: 0;
                border-bottom: none;
            }

            table {
                width: 100%;
                border-collapse: collapse;
            }

            th, td {
                text-align: left;
                padding: 10px;
                border-bottom: 1px solid #e5e7eb;
                vertical-align: top;
            }

            th {
                background: #f8fafc;
            }

            .muted {
                color: #475569;
            }

            .small-text {
                font-size: 13px;
            }

            @keyframes highPulse {
                0% {
                    box-shadow: 0 0 0 1px rgba(220, 38, 38, 0.12), 0 0 8px rgba(220, 38, 38, 0.10);
                }
                50% {
                    box-shadow: 0 0 0 1px rgba(220, 38, 38, 0.2), 0 0 22px rgba(220, 38, 38, 0.22);
                }
                100% {
                    box-shadow: 0 0 0 1px rgba(220, 38, 38, 0.12), 0 0 8px rgba(220, 38, 38, 0.10);
                }
            }

            @media (max-width: 900px) {
                .layout {
                    grid-template-columns: 1fr;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div>
                    <h1>Mini SIEM Dashboard</h1>
                    <p>Real-time SOC-style monitoring built with Python and Flask.</p>
                </div>
                <div class="header-status">
                    <p><strong>Auto Refresh:</strong> Every 5 seconds</p>
                    <p><strong>Last Updated:</strong> {{ last_updated }}</p>
                </div>
            </div>

            <div class="summary-grid">
                <div class="summary-card total">
                    <h3>Total Alerts</h3>
                    <p class="summary-number">{{ alerts|length }}</p>
                    <p class="summary-label">All detected alerts in the current scan</p>
                </div>
                <div class="summary-card high">
                    <h3>High Severity</h3>
                    <p class="summary-number">{{ high_count }}</p>
                    <p class="summary-label">Critical issues needing immediate review</p>
                </div>
                <div class="summary-card medium">
                    <h3>Medium Severity</h3>
                    <p class="summary-number">{{ medium_count }}</p>
                    <p class="summary-label">Suspicious behavior worth investigation</p>
                </div>
                <div class="summary-card low">
                    <h3>Low Severity</h3>
                    <p class="summary-number">{{ low_count }}</p>
                    <p class="summary-label">Lower-priority events for monitoring</p>
                </div>
            </div>

            <div class="layout">
                <div class="card">
                    <h2>Security Alerts</h2>
                    {% if alerts %}
                        <div class="alert-list">
                            {% for alert in alerts %}
                                <div class="alert alert-{{ alert.severity|lower }} {% if alert.is_new %}alert-new{% endif %}">
                                    <div class="alert-top">
                                        <div class="alert-meta">
                                            Rule: {{ alert.rule }} | IP: {{ alert.ip }} | Alert Time: {{ alert.alert_time_text }}
                                        </div>
                                        <div class="badge-row">
                                            <span class="badge badge-severity-{{ alert.severity|lower }}">{{ alert.severity }}</span>
                                            {% if alert.is_new %}
                                                <span class="badge badge-new">NEW</span>
                                            {% endif %}
                                        </div>
                                    </div>
                                    <div class="alert-message"><strong>{% if alert.severity == "HIGH" %}Priority Alert:{% endif %}</strong> {{ alert.message }}</div>
                                </div>
                            {% endfor %}
                        </div>
                    {% else %}
                        <div class="safe">No suspicious activity detected.</div>
                    {% endif %}
                </div>

                <div class="card">
                    <h2>What This Dashboard Checks</h2>
                    <p class="muted">The detector looks for time-based brute force attempts, sensitive file access, unknown IPs, correlated attacks, and high total risk per IP.</p>
                    <p class="muted small-text">Alerts are marked <strong>NEW</strong> when they were generated in the last 2 minutes.</p>
                </div>
            </div>

            <div class="card">
                <h2>Raw Log Events</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Event Type</th>
                            <th>User</th>
                            <th>IP Address</th>
                            <th>Resource</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for log in logs %}
                            <tr>
                                <td>{{ log.timestamp }}</td>
                                <td>{{ log.event_type }}</td>
                                <td>{{ log.user }}</td>
                                <td>{{ log.ip }}</td>
                                <td>{{ log.resource }}</td>
                            </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>

            <div class="card">
                <h2>Attack Timeline By IP</h2>
                <div class="timeline-grid">
                    {% for item in timeline %}
                        <div class="timeline-card {% if item.trusted %}trusted{% else %}untrusted{% endif %}">
                            <h3>{{ item.ip }}</h3>
                            <p class="muted">
                                Trusted: {{ "Yes" if item.trusted else "No" }} |
                                Risk Score: {{ item.risk_score }}
                            </p>
                            {% for event in item.events %}
                                <div class="timeline-event">
                                    <strong>{{ event.timestamp }}</strong><br>
                                    {{ event.event_type }} by {{ event.user }} on {{ event.resource }}
                                </div>
                            {% endfor %}
                        </div>
                    {% endfor %}
                </div>
            </div>
        </div>
    </body>
    </html>
    """

    return render_template_string(
        html,
        alerts=alerts,
        logs=logs,
        timeline=timeline,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        last_updated=last_updated,
    )


if __name__ == "__main__":
    # Debug mode is helpful for beginners while learning Flask.
    app.run(debug=True)
