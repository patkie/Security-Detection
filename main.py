import json
import sys
from parser import read_logs
from detector import detect_brute_force
from alerts import save_alerts

log_path = sys.argv[1] if len(sys.argv) > 1 else "sample_logs/auth.jsonl"
events = read_logs(log_path)

for event in events:
    print(
        f"{event['timestamp']} | "
        f"{event['source_ip']} | "
        f"{event['username']} | "
        f"{event['event']}"
    )

print(f"\nTotal events: {len(events)}")

alerts = detect_brute_force(events)
save_alerts(alerts)

print(f"\nTotal alerts: {len(alerts)}")
for alert in alerts:
    print(json.dumps(alert, indent=2))
