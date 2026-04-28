import requests
import os

def check_ip_reputation(ip):
    api_key = os.environ.get('ABUSEIPDB_API_KEY')
    
    if not api_key:
        return {'error': 'API key not set', 'ip': ip}
    
    url = 'https://api.abuseipdb.com/api/v2/check'
    
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90
    }
    
    try:
        response = requests.get(url, headers=headers, params=params)
        data = response.json()
        
        result = {
            'ip': ip,
            'abuse_score': data['data']['abuseConfidenceScore'],
            'total_reports': data['data']['totalReports'],
            'last_reported': data['data']['lastReportedAt'],
            'is_malicious': data['data']['abuseConfidenceScore'] > 25
        }
        return result
        
    except Exception as e:
        return {'error': str(e), 'ip': ip}

def check_all_ips(detection_results):
    flagged_ips = []
    
    for alert in detection_results['brute_force']:
        ip = alert['source_ip']
        print(f'[*] Checking reputation for {ip}...')
        rep = check_ip_reputation(ip)
        flagged_ips.append(rep)
    
    return flagged_ips
