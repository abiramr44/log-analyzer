# Log Analyzer — SSH Auth Log Security Tool

A Python-based log analysis tool that parses authentication logs, detects suspicious activity, checks IP reputation, and generates structured security reports in both TXT and JSON formats.

## What It Detects
- Brute force SSH login attempts and web brute force via 401/403 status codes
- Privilege escalation via sudo to root
- Failed login attempts by source IP

## Features
- Multi-format log support: auth.log, nginx, and Apache access logs
- Browser-based dashboard UI to visualize alerts (load security_report.json)
- Email alerting when HIGH severity alerts are detected
- Command line argument support: analyze any log file
- AbuseIPDB integration: real-time IP reputation checking
- Dual report output: generates both .txt and .json reports
- Modular codebase: parser, detector, reporter, reputation as separate modules

## Supported Log Formats
- auth.log: SSH brute force, failed logins, sudo escalation
- Nginx access logs: 401/403 status code spike detection
- Apache access logs: 401/403 status code spike detection

## Dashboard UI
Open dashboard.html in any browser and load security_report.json to visualize:
- Alert summary cards by severity
- Brute force attempts table with source IPs and timestamps
- Privilege escalation events
- IP reputation scores from AbuseIPDB

## Email Alerting
Configure in config.py — disabled by default. Set EMAIL_ENABLED = True and provide SMTP credentials to receive alerts when HIGH severity events are detected.

## Project Structure
log-analyzer/
├── analyzer.py       # Main entry point
├── parser.py         # Multi-format log parsing module
├── detector.py       # Detection logic
├── reporter.py       # Report generation (TXT + JSON)
├── reputation.py     # AbuseIPDB IP reputation checker
├── notifier.py       # Email alerting module
├── config.py         # Email and threshold configuration
├── dashboard.html    # Browser-based alert visualization
├── sample_logs/      # Sample auth, nginx, apache logs for testing
├── reports/          # Generated reports output here
└── requirements.txt  # Python dependencies

## Usage
python3 analyzer.py <logfile>

Examples:
python3 analyzer.py sample_logs/auth.log
python3 analyzer.py sample_logs/nginx.log
python3 analyzer.py sample_logs/apache.log

## Setup
pip install -r requirements.txt
export ABUSEIPDB_API_KEY="your_api_key_here"

Get a free API key at https://abuseipdb.com

## Detection Logic
- Brute Force (SSH): Flags any IP with 3+ failed password attempts
- Brute Force (Web): Flags any IP with 3+ 401/403 responses in nginx/apache logs
- Sudo Escalation: Flags any sudo command escalating to root
- IP Reputation: Queries AbuseIPDB for abuse confidence score on all flagged IPs

## Sample Output
[*] Starting log analysis...
[*] Target log file: sample_logs/auth.log
[+] Parsed 12 log entries
[*] Running detections...
[*] Checking IP reputation...
[+] 192.168.1.105 — Score: 0/100 | Reports: 0 | Status: CLEAN
[+] 10.0.0.55 — Score: 0/100 | Reports: 0 | Status: CLEAN
[*] Generating report...
  TOTAL ALERTS: 3

## Skills Demonstrated
- Multi-format log parsing with Python regex (auth, nginx, apache)
- Pattern-based threat detection across SSH and web attack vectors
- AbuseIPDB REST API integration
- Browser-based dashboard for security alert visualization
- SMTP email alerting for SOC workflows
- Dual format report generation (TXT + JSON)
- Modular Python architecture
- SOC-relevant alert triage logic

## Author
Abiram R — Aspiring SOC Analyst | ISC2 CC Candidate
GitHub: https://github.com/abiramr44
Medium: https://medium.com/@abiramr44
LinkedIn: https://linkedin.com/in/abiramr44
