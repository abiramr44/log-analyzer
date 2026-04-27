# Log Analyzer — SSH Auth Log Security Tool

A Python-based log analysis tool that parses Linux authentication logs,
detects suspicious activity, and generates structured security reports.

## What It Detects
- Brute force SSH login attempts (configurable threshold)
- Privilege escalation via sudo to root
- Failed login attempts by source IP

## Project Structure
log-analyzer/
├── analyzer.py       # Main entry point
├── parser.py         # Log parsing module
├── detector.py       # Detection logic
├── reporter.py       # Report generation
├── sample_logs/      # Sample auth logs for testing
├── reports/          # Generated reports output here
└── requirements.txt  # No external dependencies

## Usage
```bash
python3 analyzer.py
```

Report is saved to `reports/security_report.txt`

## Detection Logic
- **Brute Force**: Flags any IP with 3+ failed login attempts
- **Sudo Escalation**: Flags any sudo command escalating to root

## Skills Demonstrated
- Log parsing with Python regex
- Pattern-based threat detection
- Structured security reporting
- SOC-relevant alert triage logic

## Author
Abiram — Aspiring SOC Analyst | ISC2 CC Candidate
