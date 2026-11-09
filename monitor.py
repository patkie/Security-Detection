import json
import time
from pathlib import Path

from alerts import save_alerts
from detector import detect_brute_force
from parser import read_logs


def main():
    log_path = Path("data/live_auth.jsonl")
    last_version = None

    print(f"Watching {log_path}. Press Ctrl+C to stop.", flush=True)

    try:
        while True:
            try:
                stat = log_path.stat()
                version = (stat.st_ino, stat.st_size, stat.st_mtime_ns)

                if version != last_version:
                    events = read_logs(log_path)
                    new_alerts = save_alerts(detect_brute_force(events))

                    for alert in new_alerts:
                        print(json.dumps(alert, indent=2), flush=True)

                    last_version = version
            except FileNotFoundError:
                last_version = None

            time.sleep(1)
    except KeyboardInterrupt:
        print("\nMonitor stopped.")


if __name__ == "__main__":
    main()