from collections import defaultdict

BRUTE_FORCE_THRESHOLD = 3

def detect_failed_logins(parsed_lines):
    failed = []
    for line in parsed_lines:
        if 'Failed password' in line['message']:
            failed.append(line)
    return failed

def detect_brute_force(parsed_lines):
    attempts = defaultdict(list)
    
    for line in parsed_lines:
        if 'Failed password' in line['message']:
            parts = line['message'].split('from')
            if len(parts) > 1:
                ip = parts[1].strip().split()[0]
                attempts[ip].append(line)
    
    alerts = []
    for ip, events in attempts.items():
        if len(events) >= BRUTE_FORCE_THRESHOLD:
            alerts.append({
                'type': 'BRUTE_FORCE',
                'severity': 'HIGH',
                'source_ip': ip,
                'count': len(events),
                'first_seen': events[0]['timestamp'],
                'last_seen': events[-1]['timestamp']
            })
    
    return alerts

def detect_sudo_usage(parsed_lines):
    alerts = []
    for line in parsed_lines:
        if 'sudo' in line['process'] and 'USER=root' in line['message']:
            user = line['message'].split()[0]
            alerts.append({
                'type': 'SUDO_ROOT',
                'severity': 'MEDIUM',
                'user': user,
                'timestamp': line['timestamp'],
                'message': line['message']
            })
    return alerts

def run_all_detections(parsed_lines):
    return {
        'brute_force': detect_brute_force(parsed_lines),
        'sudo_usage': detect_sudo_usage(parsed_lines),
        'failed_logins': detect_failed_logins(parsed_lines)
    }
