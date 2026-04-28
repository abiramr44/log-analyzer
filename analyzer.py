import sys
from parser import parse_log_file
from detector import run_all_detections
from reporter import generate_report

REPORT_FILE = 'reports/security_report.txt'

def main():
    if len(sys.argv) < 2:
        print('[!] Usage: python3 analyzer.py <logfile>')
        print('[!] Example: python3 analyzer.py sample_logs/auth.log')
        sys.exit(1)

    LOG_FILE = sys.argv[1]

    print('[*] Starting log analysis...')
    print(f'[*] Target log file: {LOG_FILE}')

    print('[*] Parsing log file...')
    parsed_lines = parse_log_file(LOG_FILE)
    print(f'[+] Parsed {len(parsed_lines)} log entries')

    print('[*] Running detections...')
    results = run_all_detections(parsed_lines)

    print('[*] Generating report...')
    generate_report(results, REPORT_FILE)

if __name__ == '__main__':
    main()
