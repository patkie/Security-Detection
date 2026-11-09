from datetime import datetime, timedelta

def detect_brute_force(events):
    alerts = []
    failures_by_ip = {}
    last_alert_by_ip = {}

    window = timedelta(minutes=2)
    cooldown = timedelta(minutes=5)

    for event in events:
        if event["event"] != "login_failed":
            continue

        ip = event["source_ip"]
        now = datetime.fromisoformat(event["timestamp"])

        recent = failures_by_ip.get(ip, [])
        recent = [(time, log) for time, log in recent if now - time <= window]
        recent.append((now, event))
        failures_by_ip[ip] = recent

        if len(recent) < 5:
            continue

        last_alert = last_alert_by_ip.get(ip)
        if last_alert is not None and now - last_alert < cooldown:
            continue

        evidence = [log for _, log in recent]
        alerts.append({
            "rule": "Possible brute force",
            "severity": "medium",
            "source_ip": ip,
            "failure_count": len(evidence),
            "first_attempt": evidence[0]["timestamp"],
            "last_attempt": evidence[-1]["timestamp"],
            "evidence": evidence,
        })
        last_alert_by_ip[ip] = now

    return alerts