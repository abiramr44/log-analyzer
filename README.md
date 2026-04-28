# Log Analyzer — SSH Auth Log Security Tool

A Python-based log analysis tool that parses Linux authentication logs, detects suspicious activity, checks IP reputation, and generates structured security reports in both TXT and JSON formats.

## What It Detects
- Brute force SSH login attempts (configurable threshold)
- Privilege escalation via sudo to root
- Failed login attempts by source IP

## Features
- Command line argument support: analyze any log file
- AbuseIPDB integration: real-time IP reputation checking
- Dual report output: generates both .txt and .json reports
- Modular codebase: parser, detector, reporter, reputation as separate modules

## Project Structure
log-analyzer/
├── analyzer.py       # Main entry point
├── parser.py         # Log parsing module
├── detector.py       # Detection logic
├── reporter.py       # Report generation (TXT + JSON)
├── reputation.py     # AbuseIPDB IP reputation checker
├── sample_logs/      # Sample auth logs for testing
├── reports/          # Generated reports output here
└── requirements.txt  # Python dependencies

## Usage
python3 analyzer.py <logfile>

Example:
python3 analyzer.py sample_logs/auth.log

## Setup
pip install -r requirements.txt
export ABUSEIPDB_API_KEY="your_api_key_here"

Get a free API key at https://abuseipdb.com

## Detection Logic
- Brute Force: Flags any IP with 3+ failed login attempts
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
- Log parsing with Python regex
- Pattern-based threat detection
- AbuseIPDB API integration
- Dual format report generation (TXT + JSON)
- Modular Python architecture
- SOC-relevant alert triage logic

## Author
Abiram R — Aspiring SOC Analyst | ISC2 CC Candidate
GitHub: https://github.com/abiramr44
Medium: https://medium.com/@abiramr44
LinkedIn: https://linkedin.com/in/abiram-r-69896a213
