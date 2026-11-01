import re 
FAILED_RE = re.compile(r"^(?P<ts>\w{3}\s+\d+ \d{2}:\d{2}:\d{2}) \S+ sshd\[\d+]: Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
ACCEPTED_RE = re.compile(r"^(?P<ts>\w{3}\s+\d+ \d{2}:\d{2}:\d{2}) \S+ sshd\[\d+]: Accepted password for (?P<user>\S+) from (?P<ip>\S+)")


def parse_auth_line(line):
    #разбираем строку auth.log в словарь или возвращает none
    m = FAILED_RE.search(line)
    if m:
        result = m.groupdict()
        result["event"] = "failed"
        return result

    a = ACCEPTED_RE.search(line)
    if a:
        result = a.groupdict()
        result["event"] = "accepted"
        return result
        
    return None

with open("samples/auth.log", encoding="utf-8") as f:
    for line in f:
        result = parse_auth_line(line)
        print(result)
