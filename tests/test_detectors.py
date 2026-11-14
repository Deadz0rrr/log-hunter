from log_hunter.detectors import detect_login_after_fails, detect_scan


def test_login_after_fails_found():
    events = [
        {"ip": "1.1.1.1", "user": "admin", "event": "failed"},
        {"ip": "1.1.1.1", "user": "admin", "event": "failed"},
        {"ip": "1.1.1.1", "user": "admin", "event": "failed"},
        {"ip": "1.1.1.1", "user": "admin", "event": "accepted"},
    ]
    findings = detect_login_after_fails(events, 3)
    assert len(findings) == 1
    assert findings[0]["ip"] == "1.1.1.1"


def test_login_without_fails_ignored():
    events = [{"ip": "2.2.2.2", "user": "deploy", "event": "accepted"}]
    assert detect_login_after_fails(events, 3) == []


def test_scan_found():
    requests = [
        {"ip": "9.9.9.9", "path": "/.env",        "status": 404},
        {"ip": "9.9.9.9", "path": "/.git/config", "status": 404},
        {"ip": "9.9.9.9", "path": "/admin",       "status": 404},
        {"ip": "9.9.9.9", "path": "/backup.zip",  "status": 404},
        {"ip": "9.9.9.9", "path": "/config.php",  "status": 404},
        {"ip": "9.9.9.9", "path": "/wp-login.php","status": 404},
    ]
    assert detect_scan(requests) == ["9.9.9.9"]


def test_normal_user_not_scan():
    requests = [
        {"ip": "5.5.5.5", "path": "/",         "status": 200},
        {"ip": "5.5.5.5", "path": "/about",    "status": 200},
        {"ip": "5.5.5.5", "path": "/contcats", "status": 404},
    ]
    assert detect_scan(requests) == []