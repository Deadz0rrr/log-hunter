from datetime import datetime, timedelta
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

def has_burst(times, threshold, window):
    """True, если есть threshold неудач в пределах window."""
    times = sorted(times)
    for i in range(len(times) - threshold + 1):
        diff = times[i + threshold - 1] - times[i]
        if diff <= window:
            return True
    return False

def detect_bruteforce_window(events, threshold, window):
    """Возвращает список IP, у которых threshold неудач уместились в window."""
    times = collect_fail_times(events)
    suspicious = []
    for ip, ip_times in times.items():
        if has_burst(ip_times, threshold, window):
            suspicious.append(ip)
    return suspicious

def detect_login_after_fails(events, threshold):
    """Возвращает список находок: успешный вход после >= threshold неудач подряд."""
    counts = {}
    findings = []                     
    for e in events:
        if e["event"] == "failed":
            counts[e["ip"]] = counts.get(e["ip"], 0) + 1
        elif e["event"] == "accepted":
            fails = counts.get(e["ip"], 0)        
            if fails >= threshold:
                findings.append({"ip": e["ip"], "user": e["user"], "fails": fails})
            counts[e["ip"]] = 0
    return findings




if __name__ == "__main__":
    events = []
    with open("samples/auth.log", encoding="utf-8") as f:
        for line in f:
            e = parse_auth_line(line)
            if e is not None:
                events.append(e)

    print("Брутфорс:", detect_bruteforce_window(events, 5, timedelta(minutes=10)))
    print("Вход после неудач:", detect_login_after_fails(events, 3))




    