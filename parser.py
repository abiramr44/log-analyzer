import re

# Auth log pattern
AUTH_PATTERN = r'(\w+ \d+ \d+:\d+:\d+) (\w+) (\w+\[\d+\]): (.+)'

# Nginx access log pattern
NGINX_PATTERN = r'(\d+\.\d+\.\d+\.\d+) - - \[(.+?)\] "(\w+) (.+?) HTTP/[\d\.]+" (\d+) (\d+)'

# Apache access log pattern
APACHE_PATTERN = r'(\d+\.\d+\.\d+\.\d+) - (\S+) \[(.+?)\] "(\w+) (.+?) HTTP/[\d\.]+" (\d+) (\d+)'

def detect_format(line):
    if re.match(AUTH_PATTERN, line):
        return 'auth'
    elif re.match(NGINX_PATTERN, line):
        return 'nginx'
    elif re.match(APACHE_PATTERN, line):
        return 'apache'
    return None

def parse_auth_line(line):
    match = re.match(AUTH_PATTERN, line)
    if match:
        return {
            'format': 'auth',
            'timestamp': match.group(1),
            'hostname': match.group(2),
            'process': match.group(3),
            'message': match.group(4)
        }
    return None

def parse_nginx_line(line):
    match = re.match(NGINX_PATTERN, line)
    if match:
        status = int(match.group(5))
        return {
            'format': 'nginx',
            'source_ip': match.group(1),
            'timestamp': match.group(2),
            'method': match.group(3),
            'path': match.group(4),
            'status_code': status,
            'bytes': match.group(6),
            'message': f'{match.group(3)} {match.group(4)} {status}'
        }
    return None

def parse_apache_line(line):
    match = re.match(APACHE_PATTERN, line)
    if match:
        status = int(match.group(6))
        return {
            'format': 'apache',
            'source_ip': match.group(1),
            'user': match.group(2),
            'timestamp': match.group(3),
            'method': match.group(4),
            'path': match.group(5),
            'status_code': status,
            'bytes': match.group(7),
            'message': f'{match.group(4)} {match.group(5)} {status}'
        }
    return None

def parse_log_line(line):
    fmt = detect_format(line)
    if fmt == 'auth':
        return parse_auth_line(line)
    elif fmt == 'nginx':
        return parse_nginx_line(line)
    elif fmt == 'apache':
        return parse_apache_line(line)
    return None

def parse_log_file(filepath):
    parsed_lines = []
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if line:
                parsed = parse_log_line(line)
                if parsed:
                    parsed_lines.append(parsed)
    return parsed_lines
