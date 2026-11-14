from log_hunter.parsers import parse_auth_line


def test_parse_failed():
    line = "Nov  1 03:12:44 web01 sshd[2211]: Failed password for root from 203.0.113.5 port 52144 ssh2"
    result = parse_auth_line(line)
    assert result["event"] == "failed"
    assert result["ip"] == "203.0.113.5"
    assert result["user"] == "root"


def test_parse_accepted():
    line = "Nov  1 03:15:10 web01 sshd[2230]: Accepted password for deploy from 192.0.2.10 port 61000 ssh2"
    result = parse_auth_line(line)
    assert result["event"] == "accepted"
    assert result["ip"] == "192.0.2.10"
    assert result["user"] == "deploy"


def test_parse_garbage():
    line = "Nov  1 03:20:01 web01 CRON[2301]: pam_unix(cron:session): session closed for user root"
    result = parse_auth_line(line)
    assert parse_auth_line(line) is None
    