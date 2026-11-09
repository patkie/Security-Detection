import json
from datetime import datetime

def read_logs(file_path):
    events = []
    required_fields = [
        "timestamp",
        "source_ip",
        "username",
        "event",
        "host",
    ]

    with open(file_path, "r", encoding="utf-8") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            if line.strip() == "":
                continue

            try:
                event = json.loads(line)

                if not isinstance(event, dict):
                    raise ValueError("Event must be a JSON object")

                for field in required_fields:
                    if field not in event:
                        raise ValueError(f"Missing field: {field}")

                    if not isinstance(event[field], str):
                        raise ValueError(f"{field} must be text")

                    if event[field].strip() == "":
                        raise ValueError(f"{field} cannot be empty")

                timestamp = datetime.fromisoformat(
                    event["timestamp"].replace("Z", "+00:00")
                )

                if timestamp.tzinfo is None:
                    raise ValueError("Timestamp must include a timezone")

                if event["event"] not in ["login_success", "login_failed"]:
                    raise ValueError("Unknown login event type")

                events.append(event)

            except (ValueError, TypeError) as error:
                print(f"Skipping line {line_number}: {error}")

    return events