finalprojectCYB333
This Python Log Monitoring and Alerting System scans log files for suspicious activity, including failed logins, authentication failures, malware detections, blocked IP addresses, and administrative logins. Detected events are mapped to MITRE ATT&amp;CK techniques, displayed as alerts, and saved to a CSV report for analysis.

Log Monitoring and Alerting System

Project Overview

This project is a Python-based Log Monitoring and Alerting System designed to automate the detection of suspicious activity within system log files. The tool scans log entries for predefined security events and generates alerts when potentially malicious activity is identified. The project demonstrates how security automation can improve threat detection and reduce the time required to review large log files manually.

Project Objectives

The primary objectives of this project are:

* Automate the analysis of log files.
* Detect common security-related events.
* Generate alerts for suspicious activity.
* Map detected events to the MITRE ATT&CK framework.
* Export findings to a CSV report for documentation and analysis.

Features

The system currently detects:

* Failed login attempts
* Authentication failures
* Administrative account logins
* Suspicious or blocked IP addresses
* Malware detections

When a suspicious event is found, the program:

1. Displays an alert on the screen.
2. Assigns a severity level.
3. Maps the event to a MITRE ATT&CK tactic and technique.
4. Saves all alerts to a CSV file for reporting.

Project Files

```text
log_monitor.py      Main Python script
sample_logs.txt     Sample log file used for testing
alerts.csv          Generated alert report
README.md           Project documentation
```

Prerequisites

Before running the project, ensure you have:

* Python 3.8 or newer installed
* A text editor or IDE such as Visual Studio Code
* Basic knowledge of running Python scripts

Dependencies

This project uses only Python standard libraries:

```python
re
csv
datetime
```

No additional packages are required.

Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/log-monitoring-system.git
```

Navigate to the project directory:

```bash
cd log-monitoring-system
```

Running the Program

Execute the Python script:

```bash
python log_monitor.py
```

The script will:

1. Read the sample log file.
2. Search for suspicious events.
3. Display alerts in the terminal.
4. Generate an alerts.csv report.

Sample Output

```text
Security Alerts Detected

Rule: Failed Login Attempt
Severity: Medium
MITRE Technique: Brute Force - T1110

Rule: Possible Malware Detection
Severity: Critical
MITRE Technique: User Execution - T1204
```

Future Improvements

Potential enhancements include:

* Real-time log monitoring
* Email alert notifications
* Dashboard reporting
* Additional MITRE ATT&CK mappings
* Support for Windows Event Logs
* Threat intelligence integration
* Machine learning-based anomaly detection

AI Usage

AI tools including ChatGPT were used to assist with project planning, code development, troubleshooting, documentation, and testing. All code was reviewed and modified as necessary to ensure understanding of the project implementation.

## Author

Joshua Gomez

Cybersecurity Security Automation Project
