import re

def parse_log_line(line):
    pattern = r'(\w+ \d+ \d+:\d+:\d+) (\w+) (\w+\[\d+\]): (.+)'
    match = re.match(pattern, line)
    
    if match:
        return {
            'timestamp': match.group(1),
            'hostname': match.group(2),
            'process': match.group(3),
            'message': match.group(4)
        }
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
