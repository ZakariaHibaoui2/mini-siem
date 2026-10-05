# Mini SIEM — Detection Engineering Platform

> A lightweight Security Information & Event Management service. It ingests ECS-style events over a REST API, stores them in SQLite, evaluates **Sigma-inspired YAML detection rules** (single-event, threshold, and multi-event *sequence* correlation), and manages the alert lifecycle.

[![CI](https://github.com/ZakariaHibaoui2/mini-siem/actions/workflows/ci.yml/badge.svg)](https://github.com/ZakariaHibaoui2/mini-siem/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-003B57?logo=sqlite&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Demo: replaying a simulated intrusion

`examples/events.jsonl` holds 460 events of a normal morning with three attack chains hidden inside: an internet brute force that succeeds, a phishing macro that leads to encoded PowerShell, a payload in Temp, persistence, C2 over dynamic DNS and log clearing, and finally a port scan.

```text
$ minisiem replay examples/events.jsonl
replayed 460 events -> 10 alerts

  08:30:50  HIGH     AUTH-001  Brute force against a single account source       key=203.0.113.50   events=10 T1110.001
  08:31:25  CRITICAL AUTH-002  Successful logon after repeated failures          key=203.0.113.50   events=16 T1110,T1078
  08:31:25  MEDIUM   AUTH-003  Logon with a default or service account name      key=-              events=1  T1078.001
  09:10:00  HIGH     WIN-002   Encoded PowerShell command                        key=-              events=1  T1059.001,T1027
  09:10:00  HIGH     WIN-003   Office application spawning a shell               key=-              events=1  T1204.002,T1059
  09:10:30  MEDIUM   WIN-005   Executable launched from a temporary or download folder              events=1  T1204
  09:12:00  HIGH     WIN-004   New user added to local Administrators            key=-              events=1  T1098
  09:13:00  MEDIUM   NET-002   DNS query for a known-malicious or dynamic-DNS domain                events=1  T1071.004,T1568
  09:15:00  HIGH     WIN-001   Security event log cleared                        key=-              events=1  T1070.001
  09:40:20  MEDIUM   NET-001   Port scan from a single source                    key=198.51.100.23  events=20 T1046
```

That's **one alert per attack step and zero alerts from the 400+ background events**. Alert suppression (one alert per rule and key per time window) prevents alert storms: 15 failed logons produce 1 brute-force alert, not 6.

## Writing rules

```yaml
id: AUTH-002
title: Successful logon after repeated failures
severity: critical
type: sequence              # match | threshold | sequence
selection:                  # event A (all keys must match; a list means OR)
  event.category: authentication
  event.outcome: failure
followed_by:                # event B
  event.category: authentication
  event.outcome: success
group_by: source.ip         # correlation key
count: 5                    # at least 5 A's ...
timeframe: 10m              # ... then B, within 10 minutes
mitre: [T1110, T1078]
```

Field modifiers: `equals` (default), `contains`, `startswith`, `endswith`, `re`, `gt`, `lt`, `exists`, and any of them negated with `not_` (e.g. `source.ip|not_startswith: ["10.", "192.168."]`). Dotted names reach into nested ECS fields.

**Bundled rules (10):** brute force, success-after-failures, default-account logon from the internet, Security log cleared (1102), encoded PowerShell, Office spawning shells, user added to Administrators (4732), execution from Temp/Downloads, port scan, dynamic-DNS / suspicious-TLD lookups.

## API

```bash
MINISIEM_API_KEY=change-me MINISIEM_DB=siem.db uvicorn minisiem.api:app
```

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | status + rule count |
| POST | `/ingest` | one event → new alert ids |
| POST | `/ingest/batch` | up to 5000 events |
| GET | `/alerts?status=open&severity=critical` | triage queue |
| PATCH | `/alerts/{id}` | `{"status": "acknowledged" \| "closed" \| "false_positive", "note": "..."}` |
| GET | `/rules` | loaded rules |
| GET | `/stats` | events, alerts by severity/status, top rules |

All endpoints except `/health` require `X-API-Key` when `MINISIEM_API_KEY` is set. Interactive docs are at `/docs`.

```bash
docker build -t minisiem . && docker run -p 8000:8000 -e MINISIEM_API_KEY=change-me -v siem-data:/data minisiem
```

## CLI

```bash
pip install -e ".[dev]"
minisiem rules                       # validate + list rules
minisiem replay events.jsonl         # offline detection over a file
minisiem sample events.jsonl         # generate the demo stream
minisiem serve --db siem.db          # API on :8000
```

## Design notes

- **Streaming engine:** events are evaluated in time order with per-rule, per-key sliding windows (`deque`), so memory stays bounded by the timeframe.
- **Rule validation at load time:** unknown severities and types, missing `group_by`/`followed_by`, and duplicate ids are rejected before anything runs.
- **Thread-safe ingestion:** detection state is order-sensitive, so evaluation is serialised; SQLite runs in WAL mode.

## Project structure

```
src/minisiem/
├── engine.py      # rule model, modifiers, match/threshold/sequence evaluation, suppression
├── rules/*.yml    # bundled detections (auth, windows, network)
├── store.py       # SQLite events + alerts
├── api.py         # FastAPI app factory with API-key auth
├── samples.py     # ECS event stream with attack chains
└── cli.py
tests/             # 18 tests: every modifier, windows/expiry, sequences, end-to-end replay, API lifecycle
```

## License

[MIT](LICENSE)
