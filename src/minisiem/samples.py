"""Generate an ECS-style event stream with embedded attack chains (for demos and tests)."""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta
from pathlib import Path


def _auth(ts, ip, user, outcome):
    return {"@timestamp": ts.isoformat(), "event": {"category": "authentication", "outcome": outcome},
            "source": {"ip": ip}, "user": {"name": user}, "host": {"name": "web01"}}


def _proc(ts, host, parent, name, cmd, exe):
    return {"@timestamp": ts.isoformat(), "event": {"category": "process", "action": "start"},
            "host": {"name": host},
            "process": {"name": name, "command_line": cmd, "executable": exe, "parent": {"name": parent}}}


def generate(seed: int = 1) -> tuple[list[dict], set[str]]:
    """Return (events in time order, set of rule ids that the scenario should trigger)."""
    r = random.Random(seed)
    t0 = datetime(2026, 10, 5, 8, 0, 0)
    ev: list[dict] = []

    # background noise: normal logons, DNS, processes, a few allowed connections
    for i in range(400):
        ts = t0 + timedelta(seconds=i * 20 + r.randint(0, 15))
        kind = r.random()
        if kind < 0.3:
            ev.append(_auth(ts, f"10.0.0.{r.randint(2, 60)}", r.choice(["alice", "bob", "carol"]),
                            "failure" if r.random() < 0.05 else "success"))
        elif kind < 0.6:
            ev.append({"@timestamp": ts.isoformat(), "event": {"category": "dns"},
                       "dns": {"question": {"name": r.choice(["github.com", "microsoft.com", "example.org"])}},
                       "source": {"ip": f"10.0.1.{r.randint(2, 99)}"}})
        elif kind < 0.85:
            ev.append(_proc(ts, "ws-01", "explorer.exe", "chrome.exe", "chrome.exe",
                            r"C:\Program Files\Google\Chrome\chrome.exe"))
        else:
            ev.append({"@timestamp": ts.isoformat(), "event": {"category": "network", "action": "allowed"},
                       "source": {"ip": f"10.0.2.{r.randint(2, 99)}"}, "destination": {"port": 443}})

    # attack chain 1: brute force then success from the internet (AUTH-001, AUTH-002, AUTH-003)
    ts = t0 + timedelta(minutes=30)
    for _ in range(15):
        ts += timedelta(seconds=5)
        ev.append(_auth(ts, "203.0.113.50", "administrator", "failure"))
    ev.append(_auth(ts + timedelta(seconds=10), "203.0.113.50", "administrator", "success"))

    # attack chain 2: phishing macro -> encoded powershell -> payload in temp -> persistence -> cover tracks
    ts = t0 + timedelta(minutes=70)
    ev.append(_proc(ts, "ws-07", "winword.exe", "powershell.exe",
                    "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcA",
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"))
    ev.append(_proc(ts + timedelta(seconds=30), "ws-07", "powershell.exe", "update.exe", "update.exe",
                    r"C:\Users\victim\AppData\Local\Temp\update.exe"))
    ev.append({"@timestamp": (ts + timedelta(minutes=2)).isoformat(), "event": {"category": "iam"},
               "winlog": {"event_id": 4732}, "group": {"name": "Administrators"}, "user": {"name": "svc-backup"}})
    ev.append({"@timestamp": (ts + timedelta(minutes=3)).isoformat(), "event": {"category": "dns"},
               "dns": {"question": {"name": "c2-relay.duckdns.org"}}, "source": {"ip": "10.0.1.77"}})
    ev.append({"@timestamp": (ts + timedelta(minutes=5)).isoformat(), "event": {"category": "audit"},
               "winlog": {"event_id": 1102}, "host": {"name": "ws-07"}})

    # attack chain 3: port scan
    ts = t0 + timedelta(minutes=100)
    for p in range(1, 40):
        ev.append({"@timestamp": (ts + timedelta(seconds=p)).isoformat(),
                   "event": {"category": "network", "action": "blocked"},
                   "source": {"ip": "198.51.100.23"}, "destination": {"port": p * 37 % 65535}})

    ev.sort(key=lambda e: e["@timestamp"])
    expected = {"AUTH-001", "AUTH-002", "AUTH-003", "WIN-001", "WIN-002", "WIN-003", "WIN-004", "WIN-005",
                "NET-001", "NET-002"}
    return ev, expected


def write_jsonl(path: str | Path, events: list[dict]) -> None:
    Path(path).write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
