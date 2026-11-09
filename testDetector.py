import unittest
from datetime import datetime, timedelta, timezone

from detector import detect_brute_force


def make_failures(*seconds):
    start = datetime(2026, 11, 4, 14, 0, tzinfo=timezone.utc)
    return [
        {
            "timestamp": (start + timedelta(seconds=offset)).isoformat(),
            "source_ip": "192.168.1.50",
            "username": "admin",
            "event": "login_failed",
            "host": "lab-pi",
        }
        for offset in seconds
    ]


class TestBruteForceDetector(unittest.TestCase):
    def test_five_failures_trigger_one_alert(self):
        events = make_failures(0, 10, 20, 30, 40)
        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["source_ip"], "192.168.1.50")
        self.assertEqual(alerts[0]["failure_count"], 5)
        self.assertEqual(alerts[0]["evidence"], events)

    def test_four_failures_do_not_trigger_an_alert(self):
        alerts = detect_brute_force(make_failures(0, 10, 20, 30))
        self.assertEqual(alerts, [])

    def test_five_failures_spread_over_two_minutes_do_not_alert(self):
        alerts = detect_brute_force(make_failures(0, 30, 60, 90, 121))
        self.assertEqual(alerts, [])

    def test_cooldown_blocks_a_duplicate_alert(self):
        events = make_failures(0, 10, 20, 30, 40, 121)
        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["last_attempt"], events[4]["timestamp"])

    def test_new_alert_is_allowed_when_cooldown_ends(self):
        events = make_failures(0, 10, 20, 30, 40, 300, 310, 320, 330, 340)
        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 2)
        self.assertEqual(alerts[1]["evidence"], events[5:])