from parser import parse_log_file
from detector import run_all_detections
from reporter import generate_report

LOG_FILE = 'sample_logs/auth.log'
REPORT_FILE = 'reports/security_report.txt'

def main():
    print('[*] Starting log analysis...')
    
    print('[*] Parsing log file...')
    parsed_lines = parse_log_file(LOG_FILE)
    print(f'[+] Parsed {len(parsed_lines)} log entries')
    
    print('[*] Running detections...')
    results = run_all_detections(parsed_lines)
    
    print('[*] Generating report...')
    generate_report(results, REPORT_FILE)

if __name__ == '__main__':
    main()
