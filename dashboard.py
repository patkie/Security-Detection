import json
import sqlite3
from contextlib import closing
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


DB_PATH = Path(__file__).resolve().parent / "data" / "alerts.db"


class Dashboard(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/":
            self.send_error(404)
            return

        with closing(sqlite3.connect(DB_PATH.as_uri() + "?mode=ro", uri=True)) as conn:
            alerts = conn.execute("""
                SELECT rule, severity, source_ip, failure_count,
                       last_attempt, evidence_json
                FROM alerts
                ORDER BY id DESC
                LIMIT 50
            """).fetchall()

        rows = []
        for rule, severity, ip, failures, last_attempt, evidence in alerts:
            cells = "".join(
                f"<td>{escape(str(value))}</td>"
                for value in (rule, severity, ip, failures, last_attempt)
            )
            details = escape(json.dumps(json.loads(evidence), indent=2))
            rows.append(
                f"<tr>{cells}<td><details><summary>View evidence</summary>"
                f"<pre>{details}</pre></details></td></tr>"
            )

        table_rows = "".join(rows) or '<tr><td colspan="6">No alerts yet.</td></tr>'
        page = f"""<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Security Alert Dashboard</title>
    <style>
        body {{ font: 16px system-ui; margin: 2rem; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ padding: .75rem; border-bottom: 1px solid #ddd;
                  text-align: left; vertical-align: top; }}
        th {{ background: #f2f4f7; }}
        summary {{ cursor: pointer; }}
    </style>
</head>
<body>
    <h1>Security Alert Dashboard</h1>
    <p>Latest 50 saved alerts. Refresh to see new alerts.</p>
    <table>
        <thead>
            <tr><th>Rule</th><th>Severity</th><th>Source IP</th>
                <th>Failures</th><th>Last attempt (UTC)</th><th>Evidence</th></tr>
        </thead>
        <tbody>{table_rows}</tbody>
    </table>
</body>
</html>"""

        body = page.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    if not DB_PATH.is_file():
        raise SystemExit("No alerts database found. Run python3 main.py first.")

    with ThreadingHTTPServer(("127.0.0.1", 8000), Dashboard) as server:
        print("Dashboard: http://127.0.0.1:8000")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nDashboard stopped.")