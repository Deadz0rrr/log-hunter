import argparse
from datetime import timedelta
from log_hunter.parsers import parse_auth_line, parse_nginx_line
from log_hunter.detectors import detect_bruteforce_window, detect_login_after_fails, detect_scan

parser = argparse.ArgumentParser(description="log-hunter: поиск атак в логах")
parser.add_argument("--auth", help="путь к auth.log")
parser.add_argument("--nginx", help="путь к nginx access.log")       # как --auth
parser.add_argument("--threshold", type=int, default=5, help="сколько неудач считать брутфорсом")
parser.add_argument("--window", type=int, default=10, help="окно в минутах")   # как --threshold
args = parser.parse_args()

findings = []

if args.auth:
    events = []
    with open(args.auth, encoding="utf-8") as f:
        for line in f:
            e = parse_auth_line(line)
            if e is not None:
                events.append(e)

    for item in detect_login_after_fails(events, 3):
        findings.append(("HIGH", item["ip"], f"вход после {item['fails']} неудач (user: {item['user']})"))

    for ip in detect_bruteforce_window(events, args.threshold, timedelta(minutes=args.window)):
        findings.append(("MEDIUM", ip, "брутфорс SSH"))

if args.nginx:
        requests = []
        with open(args.nginx, encoding="utf-8") as f:
            for line in f:
                r = parse_nginx_line(line)
                if r is not None:
                    requests.append(r)
        for ip in detect_scan(requests):
            findings.append(("LOW", ip, "сканирование путей"))

for sev, ip, text in findings:
    print(f"[{sev:<6}] {ip:<15} {text}")
print("Найдено угроз:", len(findings))