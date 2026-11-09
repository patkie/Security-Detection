import json
import sqlite3
from contextlib import closing
from pathlib import Path

def save_alerts(alerts):
    new_alerts = []
    db_path = Path("data/alerts.db")
    db_path.parent.mkdir(exist_ok=True)

    with closing(sqlite3.connect(db_path)) as conn:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY,
                    rule TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    failure_count INTEGER NOT NULL,
                    first_attempt TEXT NOT NULL,
                    last_attempt TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    UNIQUE (rule, source_ip, last_attempt)
                )
            """)

            for alert in alerts:
                cursor = conn.execute("""
                    INSERT INTO alerts (
                        rule, severity, source_ip, failure_count,
                        first_attempt, last_attempt, evidence_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (rule, source_ip, last_attempt) DO NOTHING
                """, (
                    alert["rule"],
                    alert["severity"],
                    alert["source_ip"],
                    alert["failure_count"],
                    alert["first_attempt"],
                    alert["last_attempt"],
                    json.dumps(alert["evidence"]),
                ))

                if cursor.rowcount == 1:
                    new_alerts.append(alert)

    return new_alerts