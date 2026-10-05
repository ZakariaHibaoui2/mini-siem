"""SQLite persistence for events and alerts."""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  category TEXT,
  source_ip TEXT,
  raw TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  rule_id TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  group_key TEXT,
  ts TEXT NOT NULL,
  mitre TEXT,
  status TEXT NOT NULL DEFAULT 'open',
  event_count INTEGER NOT NULL,
  sample TEXT,
  note TEXT,
  updated_at TEXT
);
CREATE INDEX IF NOT EXISTS ix_alerts_status ON alerts(status, severity);
"""
STATUSES = ("open", "acknowledged", "closed", "false_positive")


class Store:
    def __init__(self, path: str = ":memory:"):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            self.db.executescript(SCHEMA)
            self.db.execute("PRAGMA journal_mode=WAL")

    def add_event(self, event: dict) -> int:
        cat = (event.get("event") or {}).get("category")
        sip = (event.get("source") or {}).get("ip")
        with self.lock:
            cur = self.db.execute("INSERT INTO events(ts, category, source_ip, raw) VALUES (?,?,?,?)",
                                  (str(event["@timestamp"]), cat, sip, json.dumps(event, default=str)))
            self.db.commit()
            return int(cur.lastrowid)

    def add_alert(self, det) -> int:
        r = det.rule
        with self.lock:
            cur = self.db.execute(
                "INSERT INTO alerts(rule_id,title,severity,group_key,ts,mitre,event_count,sample,updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (r.id, r.title, r.severity, det.key, det.timestamp.isoformat(), ",".join(r.mitre),
                 len(det.events), json.dumps(det.events[-1], default=str), _now()))
            self.db.commit()
            return int(cur.lastrowid)

    def alerts(self, status: str | None = None, severity: str | None = None, limit: int = 200) -> list[dict]:
        q, args = "SELECT * FROM alerts WHERE 1=1", []
        if status:
            q += " AND status=?"
            args.append(status)
        if severity:
            q += " AND severity=?"
            args.append(severity)
        q += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        with self.lock:
            return [dict(row) for row in self.db.execute(q, args)]

    def update_alert(self, alert_id: int, status: str, note: str | None = None) -> bool:
        if status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        with self.lock:
            cur = self.db.execute("UPDATE alerts SET status=?, note=COALESCE(?, note), updated_at=? WHERE id=?",
                                  (status, note, _now(), alert_id))
            self.db.commit()
            return cur.rowcount == 1

    def stats(self) -> dict:
        with self.lock:
            ev = self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            by_sev = dict(self.db.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity").fetchall())
            by_status = dict(self.db.execute("SELECT status, COUNT(*) FROM alerts GROUP BY status").fetchall())
            top = self.db.execute("SELECT rule_id, title, COUNT(*) n FROM alerts GROUP BY rule_id ORDER BY n DESC "
                                  "LIMIT 5").fetchall()
        return {"events": ev, "alerts_by_severity": by_sev, "alerts_by_status": by_status,
                "top_rules": [dict(t) for t in top]}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
