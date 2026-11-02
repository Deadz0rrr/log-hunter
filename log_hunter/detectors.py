from datetime import datetime
from log_hunter.parsers import parse_auth_line


def detect_bruteforce(events, threshold):
    """Возвращает {ip: число неудач} для IP, у которых неудач >= threshold."""
    counts = {}
    for e in events: 
        if e["event"] == "failed":           
            if e["ip"] in counts:
                counts[e["ip"]] += 1
            else:
                counts[e["ip"]] = 1

    suspicious = {}                       
    for ip, n in counts.items():          
        if n >= threshold:                
            suspicious[ip] = n            
    return suspicious  

def collect_fail_times(events, year=2026):
    """Возвращает {ip: [datetime, ...]} для неудачных входов."""
    times = {}
    for e in events:
        if e["event"] == "failed":
            t = datetime.strptime(f"{year} {e['ts']}", "%Y %b %d %H:%M:%S")
            if e["ip"] not in times:
                times[e["ip"]] = []
            times[e["ip"]].append(t)
    return times






if __name__ == "__main__":
    events = []
    with open("samples/auth.log", encoding="utf-8") as f:
        for line in f:
            e = parse_auth_line(line)
            if e is not None:        # None (cron и т.п.) не нужны
                events.append(e)
    #print(detect_bruteforce(events, 2))
    print(collect_fail_times(events))

    