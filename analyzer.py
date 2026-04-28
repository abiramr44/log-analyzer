import sys
from parser import parse_log_file
from detector import run_all_detections
from reporter import generate_report, generate_json_report
from reputation import check_all_ips

REPORT_FILE = 'reports/security_report.txt'
JSON_REPORT_FILE = 'reports/security_report.json'

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

    print('[*] Checking IP reputation...')
    reputation_results = check_all_ips(results)
    for rep in reputation_results:
        if 'error' not in rep:
            status = 'MALICIOUS' if rep['is_malicious'] else 'CLEAN'
            print(f'[+] {rep["ip"]} — Score: {rep["abuse_score"]}/100 | Reports: {rep["total_reports"]} | Status: {status}')
        else:
            print(f'[!] Could not check {rep["ip"]}: {rep["error"]}')

    print('[*] Generating report...')
    results['reputation'] = reputation_results
    generate_report(results, REPORT_FILE)
    generate_json_report(results, JSON_REPORT_FILE)

if __name__ == '__main__':
    main()
