from datetime import datetime, timedelta

import pytest
import yaml
from fastapi.testclient import TestClient

from minisiem.api import create_app
from minisiem.cli import replay
from minisiem.engine import Engine, Rule, load_rules, matches, parse_timeframe
from minisiem.samples import generate, write_jsonl

T0 = datetime(2026, 1, 1, 12, 0, 0)


def ev(sec, **fields):
    e = {"@timestamp": (T0 + timedelta(seconds=sec)).isoformat()}
    e.update(fields)
    return e


@pytest.mark.parametrize("sel,ok", [
    ({"a.b": "X"}, True),
    ({"a.b|contains": "x"}, True),
    ({"a.b|startswith": "y"}, False),
    ({"a.b|re": "^x$"}, True),
    ({"a.c|gt": 5}, True),
    ({"a.c|lt": 5}, False),
    ({"a.missing|exists": False}, True),
    ({"a.b": ["q", "x"]}, True),
    ({"a.b|not_equals": "x"}, False),
    ({"a.b": "x", "a.c|gt": 100}, False),
])
def test_modifiers(sel, ok):
    assert matches({"a": {"b": "x", "c": 7}}, sel) is ok


def test_timeframe():
    assert parse_timeframe("5m") == timedelta(minutes=5)
    with pytest.raises(ValueError):
        parse_timeframe("5 minutes")


def test_rule_validation():
    with pytest.raises(ValueError):
        Rule.from_dict({"id": "x", "title": "t", "severity": "huge", "selection": {}})
    with pytest.raises(ValueError):
        Rule.from_dict({"id": "x", "title": "t", "severity": "low", "type": "threshold", "selection": {}})


def test_bundled_rules_load():
    rules = load_rules()
    assert len(rules) == 10
    assert all(r.mitre for r in rules)


def test_threshold_rule_fires_once_per_window():
    rule = Rule.from_dict(yaml.safe_load("""
id: T1
title: many
severity: low
type: threshold
selection: {kind: fail}
group_by: ip
count: 3
timeframe: 1m
"""))
    eng = Engine([rule])
    hits = [d for i in range(10) for d in eng.process(ev(i, kind="fail", ip="1.1.1.1"))]
    assert len(hits) == 1 and len(hits[0].events) == 3
    assert eng.process(ev(5, kind="fail", ip="2.2.2.2")) == []


def test_threshold_window_expires():
    rule = Rule.from_dict({"id": "T", "title": "t", "severity": "low", "type": "threshold", "selection": {"k": 1},
                           "group_by": "ip", "count": 3, "timeframe": "10s"})
    eng = Engine([rule])
    hits = [d for s in (0, 20, 40, 60) for d in eng.process(ev(s, k=1, ip="x"))]
    assert hits == []


def test_sequence_rule():
    rule = Rule.from_dict({"id": "S", "title": "s", "severity": "critical", "type": "sequence",
                           "selection": {"o": "fail"}, "followed_by": {"o": "ok"}, "group_by": "ip",
                           "count": 3, "timeframe": "5m"})
    eng = Engine([rule])
    assert eng.process(ev(0, o="ok", ip="a")) == []               # success alone: nothing
    for i in range(3):
        eng.process(ev(i + 1, o="fail", ip="a"))
    hits = eng.process(ev(10, o="ok", ip="a"))
    assert len(hits) == 1 and len(hits[0].events) == 4


def test_sample_stream_triggers_every_rule_without_noise(tmp_path):
    events, expected = generate()
    path = tmp_path / "e.jsonl"
    write_jsonl(path, events)
    dets = replay(str(path))
    fired = {d.rule.id for d in dets}
    assert fired == expected
    assert all(not d.key.startswith("10.0.0.") for d in dets if d.rule.id.startswith("AUTH"))


def test_api_flow():
    client = TestClient(create_app(api_key="secret"))
    h = {"x-api-key": "secret"}
    assert client.get("/alerts").status_code == 401
    events, _ = generate()
    r = client.post("/ingest/batch", json=events, headers=h).json()
    assert r["ingested"] == len(events) and len(r["alerts"]) >= 10
    crit = client.get("/alerts?severity=critical", headers=h).json()
    assert crit and crit[0]["rule_id"] == "AUTH-002"
    aid = crit[0]["id"]
    assert client.patch(f"/alerts/{aid}", json={"status": "acknowledged", "note": "on it"}, headers=h).status_code == 200
    assert client.patch(f"/alerts/{aid}", json={"status": "weird"}, headers=h).status_code == 422
    assert client.patch("/alerts/99999", json={"status": "closed"}, headers=h).status_code == 404
    stats = client.get("/stats", headers=h).json()
    assert stats["events"] == len(events) and stats["alerts_by_status"]["acknowledged"] == 1
    assert len(client.get("/rules", headers=h).json()) == 10
