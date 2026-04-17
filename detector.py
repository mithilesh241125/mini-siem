"""
detector.py

This module reads log data and applies beginner-friendly SIEM rules.
The goal is to keep the code clear while still looking more like a
real SOC monitoring workflow.
"""

from datetime import datetime, timedelta


# These IP addresses are treated as normal or trusted.
TRUSTED_IPS = {
    "192.168.1.10",
    "192.168.1.20",
    "10.0.0.5",
}


# Simple risk scoring values used by the risk score rule.
RISK_VALUES = {
    "LOGIN_FAILED": 2,
    "UNKNOWN_IP": 3,
    "SENSITIVE_FILE": 5,
}


def parse_timestamp(timestamp_text):
    """
    Convert a timestamp string into a Python datetime object.
    """
    return datetime.strptime(timestamp_text, "%Y-%m-%d %H:%M:%S")


def load_logs(file_path):
    """
    Read logs from a text file and convert each line into a dictionary.

    Expected format:
    timestamp,event_type,user,ip,resource
    """
    logs = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            parts = line.split(",")

            if len(parts) != 5:
                continue

            log = {
                "timestamp": parts[0],
                "event_type": parts[1],
                "user": parts[2],
                "ip": parts[3],
                "resource": parts[4],
                "parsed_time": parse_timestamp(parts[0]),
            }
            logs.append(log)

    # Sort logs so all detections and timelines stay in time order.
    logs.sort(key=lambda log: log["parsed_time"])
    return logs


def create_alert(message, severity, ip, rule_name, alert_time=None):
    """
    Build one alert object. Using a dictionary keeps the app simple.
    """
    return {
        "message": message,
        "severity": severity,
        "ip": ip,
        "rule": rule_name,
        "alert_time": alert_time,
    }


def detect_brute_force(logs):
    """
    Detect brute force behavior when 5 failed logins happen within 2 minutes
    from the same IP address.
    """
    alerts = []
    failed_by_ip = {}
    time_window = timedelta(minutes=2)

    for log in logs:
        if log["event_type"] != "LOGIN_FAILED":
            continue

        ip = log["ip"]
        failed_by_ip.setdefault(ip, []).append(log["parsed_time"])

    for ip, failed_times in failed_by_ip.items():
        for index in range(len(failed_times) - 4):
            start_time = failed_times[index]
            end_time = failed_times[index + 4]

            if end_time - start_time <= time_window:
                message = (
                    f"Brute force detected from {ip}: 5 failed login attempts "
                    f"within 2 minutes."
                )
                alerts.append(
                    create_alert(
                        message,
                        "HIGH",
                        ip,
                        "Brute Force",
                        failed_times[index + 4],
                    )
                )
                break

    return alerts


def detect_sensitive_file_access(logs):
    """
    Detect access to a sensitive file named secret.txt.
    """
    alerts = []

    for log in logs:
        if log["resource"] == "secret.txt":
            message = (
                f"Sensitive file access detected: user {log['user']} accessed "
                f"secret.txt from {log['ip']}."
            )
            alerts.append(
                create_alert(
                    message,
                    "MEDIUM",
                    log["ip"],
                    "Sensitive File Access",
                    log["parsed_time"],
                )
            )

    return alerts


def detect_unknown_ips(logs):
    """
    Detect events coming from IP addresses outside the trusted list.
    """
    alerts = []

    for log in logs:
        if log["ip"] not in TRUSTED_IPS:
            message = (
                f"Unknown IP detected: {log['ip']} used by {log['user']} for "
                f"event {log['event_type']}."
            )
            alerts.append(
                create_alert(
                    message,
                    "LOW",
                    log["ip"],
                    "Unknown IP",
                    log["parsed_time"],
                )
            )

    return alerts


def detect_correlated_attacks(logs):
    """
    Detect a simple multi-stage attack pattern:
    LOGIN_FAILED -> LOGIN_FAILED -> FILE_ACCESS
    from the same IP address.
    """
    alerts = []
    grouped_logs = group_logs_by_ip(logs)

    for ip, entries in grouped_logs.items():
        event_types = [entry["event_type"] for entry in entries]

        for index in range(len(event_types) - 2):
            window = event_types[index:index + 3]

            if window == ["LOGIN_FAILED", "LOGIN_FAILED", "FILE_ACCESS"]:
                message = (
                    f"Possible multi-stage attack detected from {ip}: "
                    f"LOGIN_FAILED -> LOGIN_FAILED -> FILE_ACCESS."
                )
                alerts.append(
                    create_alert(
                        message,
                        "HIGH",
                        ip,
                        "Attack Correlation",
                        entries[index + 2]["parsed_time"],
                    )
                )
                break

    return alerts


def calculate_risk_scores(logs):
    """
    Calculate a risk score for each IP.

    Score rules:
    LOGIN_FAILED = +2
    UNKNOWN_IP = +3
    SENSITIVE_FILE = +5
    """
    scores = {}

    for log in logs:
        ip = log["ip"]
        scores.setdefault(ip, 0)

        if log["event_type"] == "LOGIN_FAILED":
            scores[ip] += RISK_VALUES["LOGIN_FAILED"]

        if log["ip"] not in TRUSTED_IPS:
            scores[ip] += RISK_VALUES["UNKNOWN_IP"]

        if log["resource"] == "secret.txt":
            scores[ip] += RISK_VALUES["SENSITIVE_FILE"]

    return scores


def detect_high_risk_ips(risk_scores):
    """
    Raise a HIGH severity alert if an IP risk score goes above 8.
    """
    alerts = []

    for ip, score in risk_scores.items():
        if score > 8:
            message = f"High risk activity detected from {ip} with risk score {score}."
            alerts.append(create_alert(message, "HIGH", ip, "Risk Score"))

    return alerts


def group_logs_by_ip(logs):
    """
    Group logs by IP address so the UI can display an attack timeline.
    """
    grouped_logs = {}

    for log in logs:
        ip = log["ip"]
        grouped_logs.setdefault(ip, []).append(log)

    return grouped_logs


def build_attack_timeline(logs, risk_scores):
    """
    Build a simple timeline per IP with ordered events and total risk.
    """
    grouped_logs = group_logs_by_ip(logs)
    timeline = []

    for ip in sorted(grouped_logs.keys()):
        entries = grouped_logs[ip]
        timeline_events = []

        for entry in entries:
            timeline_events.append(
                {
                    "timestamp": entry["timestamp"],
                    "event_type": entry["event_type"],
                    "user": entry["user"],
                    "resource": entry["resource"],
                }
            )

        timeline.append(
            {
                "ip": ip,
                "trusted": ip in TRUSTED_IPS,
                "risk_score": risk_scores.get(ip, 0),
                "events": timeline_events,
            }
        )

    return timeline


def remove_duplicate_alerts(alerts):
    """
    Remove duplicate alerts while keeping the original order.
    """
    unique_alerts = []
    seen = set()

    for alert in alerts:
        alert_key = (alert["message"], alert["severity"], alert["ip"], alert["rule"])

        if alert_key not in seen:
            unique_alerts.append(alert)
            seen.add(alert_key)

    return unique_alerts


def analyze_logs(logs):
    """
    Run every SIEM feature and return all dashboard data.
    """
    risk_scores = calculate_risk_scores(logs)

    alerts = []
    alerts.extend(detect_brute_force(logs))
    alerts.extend(detect_sensitive_file_access(logs))
    alerts.extend(detect_unknown_ips(logs))
    alerts.extend(detect_correlated_attacks(logs))
    alerts.extend(detect_high_risk_ips(risk_scores))

    alerts = remove_duplicate_alerts(alerts)
    timeline = build_attack_timeline(logs, risk_scores)

    return {
        "alerts": alerts,
        "risk_scores": risk_scores,
        "timeline": timeline,
    }
