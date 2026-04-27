from datetime import datetime

def generate_report(detection_results, output_path):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    lines = []
    lines.append('=' * 60)
    lines.append('       LOG ANALYSIS SECURITY REPORT')
    lines.append(f'       Generated: {now}')
    lines.append('=' * 60)
    
    # Brute Force Section
    lines.append('\n[HIGH] BRUTE FORCE ATTEMPTS')
    lines.append('-' * 40)
    bf_alerts = detection_results['brute_force']
    if bf_alerts:
        for alert in bf_alerts:
            lines.append(f'  Source IP   : {alert["source_ip"]}')
            lines.append(f'  Attempts    : {alert["count"]}')
            lines.append(f'  First Seen  : {alert["first_seen"]}')
            lines.append(f'  Last Seen   : {alert["last_seen"]}')
            lines.append('')
    else:
        lines.append('  No brute force activity detected.\n')

    # Sudo Usage Section
    lines.append('[MEDIUM] PRIVILEGE ESCALATION (sudo to root)')
    lines.append('-' * 40)
    sudo_alerts = detection_results['sudo_usage']
    if sudo_alerts:
        for alert in sudo_alerts:
            lines.append(f'  User        : {alert["user"]}')
            lines.append(f'  Timestamp   : {alert["timestamp"]}')
            lines.append(f'  Command     : {alert["message"]}')
            lines.append('')
    else:
        lines.append('  No sudo escalation detected.\n')

    # Summary
    total_alerts = len(bf_alerts) + len(sudo_alerts)
    lines.append('=' * 60)
    lines.append(f'  TOTAL ALERTS: {total_alerts}')
    lines.append('=' * 60)

    report = '\n'.join(lines)
    
    with open(output_path, 'w') as f:
        f.write(report)
    
    print(report)
    print(f'\nReport saved to: {output_path}')
