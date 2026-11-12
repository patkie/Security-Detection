# Brute-Force Login Detection

I built this project to see if I could spot a burst of failed logins in SSH logs and trace an alert back to the events that triggered it. The Python script flags an IP when it reaches five failed logins within two minutes. It saves the alert and the matching log entries in SQLite so I can review them in a local dashboard.

I tested the detector on a Raspberry Pi using controlled SSH login attempts. I also tried the same rule in Splunk Cloud with the synthetic logs included in this repo.

## Run it locally

You’ll need Python 3.11 or newer. There’s nothing extra to install. From the repo folder, run:

```bash
python3 -m unittest -v testDetector
python3 main.py
python3 dashboard.py
```

The first command runs the tests. The second processes the sample logs and should print one alert: `192.168.1.50` had five failed logins in 80 seconds.

Once the dashboard starts, open [http://127.0.0.1:8000](http://127.0.0.1:8000). Click **View evidence** to see the log entries that triggered the alert. Press **Ctrl+C** in the terminal when you’re done.

## How it works

`parser.py` reads and validates the logs. `detector.py` counts recent failures by IP and uses a five-minute cooldown so the same IP doesn’t keep triggering alerts. `alerts.py` saves the results to SQLite, and `dashboard.py` displays them.

I also wrote `simulate_logs.py` to generate test data and `import_ssh_logs.py` to convert SSH journal entries into a format the detector can read.

## What I found in Splunk

The sample had eight login events: six failures and two successes. Five of those failures came from `192.168.1.50` within 80 seconds, so Splunk flagged the same IP as my Python script.

![Splunk dashboard showing the brute-force match and overall login counts](splunk-dashboard.png)

I then pulled up all the login events from that IP and put them in time order. All five attempts targeted `admin`, and none succeeded in the sample.

![Splunk investigation timeline showing five failed attempts against admin](splunk-investigation.png)

### Try the Splunk search

Upload `sample_logs/auth.jsonl` using the `_json` source type. In **Search & Reporting**, set the time range to **All time** and run:

```spl
source="auth.jsonl" event="login_failed"
| sort 0 +_time
| streamstats time_window=2m count AS failures min(_time) AS first_failure BY source_ip
| where failures=5
| eval elapsed_seconds=_time-first_failure
| table source_ip failures elapsed_seconds
```

You should get one row: `192.168.1.50`, five failures, 80 seconds.

I also doubled the gaps between the attempts in a test search. The same five failures then took 160 seconds, so the search returned no match. That let me check that the rule was using the two-minute window, rather than just counting five failures.
