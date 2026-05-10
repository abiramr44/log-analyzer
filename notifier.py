import smtplib
import config
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_alert(detection_results, report_path):
    if not config.EMAIL_ENABLED:
        return

    bf_count = len(detection_results['brute_force'])
    sudo_count = len(detection_results['sudo_usage'])
    total = bf_count + sudo_count

    try:
        msg = MIMEMultipart()
        msg['From'] = config.EMAIL_SENDER
        msg['To'] = config.EMAIL_RECEIVER
        msg['Subject'] = f'[Log-Analyzer ALERT] {total} HIGH Severity Alerts Detected'

        body = f"""
Log-Analyzer Security Alert
============================
Total Alerts      : {total}
Brute Force       : {bf_count}
Privilege Escalation : {sudo_count}

Brute Force Sources:
"""
        for alert in detection_results['brute_force']:
            body += f"  - {alert['source_ip']} ({alert['count']} attempts)\n"

        body += f"\nFull report saved to: {report_path}\n"

        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(config.EMAIL_SMTP, config.EMAIL_PORT)
        server.starttls()
        server.login(config.EMAIL_SENDER, config.EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()

        print(f'[+] Alert email sent to {config.EMAIL_RECEIVER}')

    except Exception as e:
        print(f'[!] Email failed: {e}')
