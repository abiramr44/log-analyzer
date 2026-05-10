# Log Analyzer — SSH Auth Log Security Tool

A Python-based log analysis tool that parses authentication logs, detects suspicious activity, checks IP reputation, and generates structured security reports in both TXT and JSON formats.

## What It Detects
- Brute force SSH login attempts (configurable threshold)
- Privilege escalation via sudo to root
- Failed login attempts by source IP

## Features
- Multi-format log support: parse nginx, Apache, and syslog formats in addition to auth logs
- Dashboard UI to visualize alerts and security events
- Email alerting when HIGH severity alerts are detected
- Command line argument support: analyze any log file
- AbuseIPDB integration: real-time IP reputation checking
- Dual report output: generates both .txt and .json reports
- Modular codebase: parser, detector, reporter, reputation as separate modules

## Multi-Format Support
The tool now supports multiple log formats beyond standard auth logs:

- **Nginx Access Logs** — Detect suspicious web requests, scanning patterns, and potential web attacks
- **Apache Access Logs** — Monitor for exploit attempts, path traversal, and abnormal request patterns
- **Syslog** — Parse system-wide logs for broader security event correlation

Each format has dedicated parsing rules while maintaining consistent detection logic across all sources.

## Dashboard UI
A web-based dashboard provides real-time visualization of alerts and security events:

- Alert summary cards showing total alerts by severity
- Time-series graphs of alert frequency
- Top offending IPs with reputation scores
- Filterable alert table with drill-down capabilities
- Export reports directly from the dashboard

Access the dashboard by running the web interface after log analysis.

## Email Alerting
When HIGH severity alerts are detected (such as brute force attacks with high-confidence IP reputation scores), the tool can send immediate email notifications to SOC analysts.

### Email Configuration
Configure SMTP settings including server, port, authentication, and recipient addresses. HIGH severity triggers include scenarios like 10+ failed attempts from a single IP or an IP with AbuseIPDB confidence score above 85%.

### Alert Content
Each email includes the severity level, timestamp, alert type, affected source IP, reputation data if applicable, and a summary of the triggering event.

## Project Structure
log-analyzer/
├── analyzer.py       # Main entry point
├── parser.py         # Log parsing module (multi-format support)
├── detector.py       # Detection logic with severity levels
├── reporter.py       # Report generation (TXT + JSON)
├── reputation.py     # AbuseIPDB IP reputation checker
├── dashboard.py      # Web dashboard UI
├── alert.py          # Email alerting module
├── sample_logs/      # Sample logs for testing
├── reports/          # Generated reports output here
└── requirements.txt  # Python dependencies

## Usage
Command line:
python3 analyzer.py <logfile>

Examples:
python3 analyzer.py sample_logs/auth.log
python3 analyzer.py sample_logs/nginx_access.log
python3 analyzer.py sample_logs/syslog.log

Dashboard:
python3 dashboard.py
Then open browser to http://localhost:5000

## Setup
pip install -r requirements.txt
export ABUSEIPDB_API_KEY="your_api_key_here"

For email alerts, configure SMTP settings in config.py.
For dashboard, additional web framework dependencies will be installed via requirements.txt.

Get a free API key at https://abuseipdb.com

## Detection Logic
- Brute Force: Flags any IP with 3+ failed login attempts (HIGH severity for 10+ attempts)
- Sudo Escalation: Flags any sudo command escalating to root
- IP Reputation: Queries AbuseIPDB for abuse confidence score on all flagged IPs
- Severity Levels: LOW, MEDIUM, HIGH based on attempt counts and reputation scores

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
[*] HIGH severity alert detected — email notification sent

## Skills Demonstrated
- Multi-format log parsing with Python regex (nginx, Apache, syslog, auth)
- Pattern-based threat detection with severity scoring
- AbuseIPDB API integration
- Web dashboard development for security visualization
- SMTP email alerting for SOC workflows
- Dual format report generation (TXT + JSON)
- Modular Python architecture
- SOC-relevant alert triage logic

## Author
Abiram R — Aspiring SOC Analyst | ISC2 CC Candidate
GitHub: https://github.com/abiramr44
Medium: https://medium.com/@abiramr44
LinkedIn: https://linkedin.com/in/abiramr44

---

Let me know if you need any adjustments or if you have more README updates to work on!
