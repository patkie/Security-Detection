import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Generate fake login logs.")
    parser.add_argument("scenario", choices=["normal", "brute-force"])
    args = parser.parse_args()

    start = datetime.now(timezone.utc)

    def make_event(seconds, ip, username, event_type):
        return {
            "timestamp": (start + timedelta(seconds=seconds))
            .isoformat().replace("+00:00", "Z"),
            "source_ip": ip,
            "username": username,
            "event": event_type,
            "host": "lab-pi",
        }

    events = [
        make_event(0, "192.0.2.10", "alice", "login_success"),
        make_event(5, "192.0.2.20", "bob", "login_failed"),
        make_event(10, "192.0.2.20", "bob", "login_success"),
    ]

    if args.scenario == "brute-force":
        for seconds in range(20, 70, 10):
            events.append(
                make_event(seconds, "203.0.113.50", "admin", "login_failed")
            )

    output = Path("data/simulated_auth.jsonl")
    output.parent.mkdir(exist_ok=True)
    with output.open("w", encoding="utf-8") as file:
        for event in events:
            file.write(json.dumps(event) + "\n")

    print(f"Wrote {len(events)} events to {output}")


if __name__ == "__main__":
    main()