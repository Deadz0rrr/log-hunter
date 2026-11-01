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

    suspicious = {}                       # 1. пустой словарь для находок, ДО цикла
    for ip, n in counts.items():          # 2. идём по парам ip-счёт
        if n >= threshold:                # 3. только где неудач не меньше порога
            suspicious[ip] = n            # 4. кладём пару в находки (вместо print)
    return suspicious  


if __name__ == "__main__":
    events = []
    with open("samples/auth.log", encoding="utf-8") as f:
        for line in f:
            e = parse_auth_line(line)
            if e is not None:        # None (cron и т.п.) не нужны
                events.append(e)
    print(detect_bruteforce(events, 2))


    