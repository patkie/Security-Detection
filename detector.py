from datetime import datetime, timedelta

def detect_brute_force(events):
    failures_by_ip = {}
    window = timedelta(minutes=2)

    for event in events:
        if event["event"] != "login_failed":
            continue

        ip = event["source_ip"]
        now = datetime.fromisoformat(event["timestamp"])
        recent = failures_by_ip.get(ip, [])

        recent = [time for time in recent if now - time <= window]
        recent.append(now)
        failures_by_ip[ip] = recent

        if len(recent) == 5:
            print(f"Possible brute force: {ip} had 5 failed logins within 2 minutes")