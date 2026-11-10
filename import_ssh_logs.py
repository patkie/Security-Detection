import json
import re
import sys
from datetime import datetime, timedelta, timezone

LOGIN = re.compile(
    r"^(?P<result>Failed|Accepted) password for (?:invalid user )?"
    r"(?P<username>\S+) from (?P<ip>\S+) port \d+"
)
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def main():
    for line in sys.stdin:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        message = entry.get("MESSAGE")
        if not isinstance(message, str):
            continue

        match = LOGIN.match(message)
        if not match:
            continue

        timestamp = EPOCH + timedelta(
            microseconds=int(entry["__REALTIME_TIMESTAMP"])
        )
        event = {
            "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
            "source_ip": match["ip"],
            "username": match["username"],
            "event": (
                "login_failed" if match["result"] == "Failed" else "login_success"
            ),
            "host": entry.get("_HOSTNAME", "raspberrypi"),
        }
        print(json.dumps(event))


if __name__ == "__main__":
    main()