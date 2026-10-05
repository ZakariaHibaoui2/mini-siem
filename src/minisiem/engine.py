"""Sigma-inspired detection engine.

Rule types
----------
* ``match``      - a single event satisfies the selection.
* ``threshold``  - at least ``count`` matching events with the same ``group_by`` value within ``timeframe``.
* ``sequence``   - event A followed by event B with the same ``group_by`` value within ``timeframe``
                   (e.g. many failures then a success).

Selections map ``field|modifier`` to a value or list of values (list = OR). All keys must match (AND).
Modifiers: equals (default), contains, startswith, endswith, re, gt, lt, exists. Prefix ``not_`` negates.
"""
from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

SEVERITIES = ("informational", "low", "medium", "high", "critical")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


def parse_timeframe(text: str) -> timedelta:
    m = re.fullmatch(r"(\d+)([smhd])", str(text).strip())
    if not m:
        raise ValueError(f"invalid timeframe '{text}' (use e.g. 30s, 5m, 1h)")
    return timedelta(**{_UNITS[m.group(2)]: int(m.group(1))})


def get_field(event: dict, dotted: str) -> Any:
    cur: Any = event
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _match_one(actual: Any, modifier: str, expected: Any) -> bool:
    if modifier == "exists":
        return (actual is not None) == bool(expected)
    if actual is None:
        return False
    if modifier in {"gt", "lt"}:
        try:
            return float(actual) > float(expected) if modifier == "gt" else float(actual) < float(expected)
        except (TypeError, ValueError):
            return False
    a, e = str(actual).lower(), str(expected).lower()
    return {
        "equals": a == e,
        "contains": e in a,
        "startswith": a.startswith(e),
        "endswith": a.endswith(e),
        "re": re.search(str(expected), str(actual), re.I) is not None,
    }[modifier]


def matches(event: dict, selection: dict) -> bool:
    for key, expected in selection.items():
        name, _, modifier = key.partition("|")
        modifier = modifier or "equals"
        negate = modifier.startswith("not_")
        modifier = modifier.removeprefix("not_")
        values = expected if isinstance(expected, list) else [expected]
        hit = any(_match_one(get_field(event, name), modifier, v) for v in values)
        if hit == negate:
            return False
    return True


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    type: str
    selection: dict = field(default_factory=dict)
    followed_by: dict = field(default_factory=dict)
    group_by: str = ""
    count: int = 1
    timeframe: timedelta = timedelta(minutes=5)
    mitre: list[str] = field(default_factory=list)
    description: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> Rule:
        missing = {"id", "title", "severity", "selection"} - d.keys()
        if missing:
            raise ValueError(f"rule {d.get('id', '?')}: missing {sorted(missing)}")
        if d["severity"] not in SEVERITIES:
            raise ValueError(f"rule {d['id']}: bad severity {d['severity']}")
        rtype = d.get("type", "match")
        if rtype not in {"match", "threshold", "sequence"}:
            raise ValueError(f"rule {d['id']}: bad type {rtype}")
        if rtype in {"threshold", "sequence"} and not d.get("group_by"):
            raise ValueError(f"rule {d['id']}: {rtype} rules need group_by")
        if rtype == "sequence" and not d.get("followed_by"):
            raise ValueError(f"rule {d['id']}: sequence rules need followed_by")
        return cls(
            id=d["id"], title=d["title"], severity=d["severity"], type=rtype, selection=d["selection"],
            followed_by=d.get("followed_by", {}), group_by=d.get("group_by", ""), count=int(d.get("count", 1)),
            timeframe=parse_timeframe(d.get("timeframe", "5m")), mitre=list(d.get("mitre", [])),
            description=d.get("description", ""),
        )


def load_rules(path: str | Path | None = None) -> list[Rule]:
    folder = Path(path) if path else Path(__file__).parent / "rules"
    rules = []
    for f in sorted(folder.glob("*.y*ml")):
        for doc in yaml.safe_load_all(f.read_text(encoding="utf-8")):
            if doc:
                rules.append(Rule.from_dict(doc))
    ids = [r.id for r in rules]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate rule ids")
    return rules


@dataclass
class Detection:
    rule: Rule
    key: str
    timestamp: datetime
    events: list[dict]


class Engine:
    """Stateful streaming evaluator: feed events in time order, get detections back."""

    def __init__(self, rules: list[Rule]):
        self.rules = rules
        self._windows: dict[tuple[str, str], deque] = defaultdict(deque)
        self._pending: dict[tuple[str, str], deque] = defaultdict(deque)
        self._fired: dict[tuple[str, str], datetime] = {}

    @staticmethod
    def _ts(event: dict) -> datetime:
        ts = event.get("@timestamp") or event.get("timestamp")
        return ts if isinstance(ts, datetime) else datetime.fromisoformat(str(ts).replace("Z", "+00:00"))

    def _suppressed(self, rule: Rule, key: str, ts: datetime) -> bool:
        """One alert per rule+key per timeframe (avoid alert storms)."""
        last = self._fired.get((rule.id, key))
        if last and ts - last < rule.timeframe:
            return True
        self._fired[(rule.id, key)] = ts
        return False

    def process(self, event: dict) -> list[Detection]:
        ts = self._ts(event)
        out = []
        for rule in self.rules:
            key = str(get_field(event, rule.group_by)) if rule.group_by else ""
            if rule.type == "match":
                if matches(event, rule.selection) and not self._suppressed(rule, key or str(id(event)), ts):
                    out.append(Detection(rule, key, ts, [event]))
            elif rule.type == "threshold":
                if not matches(event, rule.selection):
                    continue
                q = self._windows[(rule.id, key)]
                q.append(event)
                while q and ts - self._ts(q[0]) > rule.timeframe:
                    q.popleft()
                if len(q) >= rule.count and not self._suppressed(rule, key, ts):
                    out.append(Detection(rule, key, ts, list(q)))
            else:  # sequence
                q = self._pending[(rule.id, key)]
                while q and ts - self._ts(q[0]) > rule.timeframe:
                    q.popleft()
                if matches(event, rule.followed_by) and len(q) >= rule.count:
                    if not self._suppressed(rule, key, ts):
                        out.append(Detection(rule, key, ts, list(q) + [event]))
                    q.clear()
                elif matches(event, rule.selection):
                    q.append(event)
        return out
