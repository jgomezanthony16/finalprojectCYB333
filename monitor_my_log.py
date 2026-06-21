import re
import csv
from datetime import datetime

LOG_FILE = "sample_logs.txt"
OUTPUT_FILE = "alerts.csv"

RULES = [
    {
        "name": "Failed Login Attempt",
        "pattern": r"failed login|login failed|authentication failure",
        "severity": "Medium",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "Brute Force - T1110"
    },
    {
        "name": "Successful Admin Login",
        "pattern": r"admin login successful|root login successful",
        "severity": "High",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "Valid Accounts - T1078"
    },
    {
        "name": "Suspicious IP Activity",
        "pattern": r"blocked ip|suspicious ip|blacklisted ip",
        "severity": "High",
        "mitre_tactic": "Command and Control",
        "mitre_technique": "Application Layer Protocol - T1071"
    },
    {
        "name": "Possible Malware Detection",
        "pattern": r"malware detected|trojan|virus found",
        "severity": "Critical",
        "mitre_tactic": "Execution",
        "mitre_technique": "User Execution - T1204"
    }
]


def read_logs(file_path):
    try:
        with open(file_path, "r") as file:
            return file.readlines()
    except FileNotFoundError:
        print(f"Error: {file_path} was not found.")
        return []


def analyze_logs(log_lines):
    alerts = []

    for line_number, line in enumerate(log_lines, start=1):
        for rule in RULES:
            if re.search(rule["pattern"], line, re.IGNORECASE):
                alert = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "line_number": line_number,
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "mitre_tactic": rule["mitre_tactic"],
                    "mitre_technique": rule["mitre_technique"],
                    "log_entry": line.strip()
                }
                alerts.append(alert)

    return alerts


def save_alerts(alerts, output_file):
    if not alerts:
        print("No suspicious activity found.")
        return

    fieldnames = [
        "timestamp",
        "line_number",
        "rule_name",
        "severity",
        "mitre_tactic",
        "mitre_technique",
        "log_entry"
    ]

    with open(output_file, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(alerts)

    print(f"{len(alerts)} alert(s) saved to {output_file}")


def print_alerts(alerts):
    if not alerts:
        return

    print("\nSecurity Alerts Detected:")
    print("-" * 60)

    for alert in alerts:
        print(f"Rule: {alert['rule_name']}")
        print(f"Severity: {alert['severity']}")
        print(f"MITRE Tactic: {alert['mitre_tactic']}")
        print(f"MITRE Technique: {alert['mitre_technique']}")
        print(f"Log Entry: {alert['log_entry']}")
        print("-" * 60)


def main():
    logs = read_logs(LOG_FILE)
    alerts = analyze_logs(logs)
    print_alerts(alerts)
    save_alerts(alerts, OUTPUT_FILE)


if __name__ == "__main__":
    main()
