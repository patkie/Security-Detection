from parser import read_logs
from detector import detect_brute_force

events = read_logs("sample_logs/auth.jsonl")

for event in events:
    print(
        f"{event['timestamp']} | "
        f"{event['source_ip']} | "
        f"{event['username']} | "
        f"{event['event']}"
    )

print(f"\nTotal events: {len(events)}")
detect_brute_force(events)