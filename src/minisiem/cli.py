"""minisiem command line: validate rules, replay event files offline, run the API."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from .engine import Engine, load_rules
from .samples import generate, write_jsonl


def replay(path: str, rules_dir: str | None = None) -> list:
    engine = Engine(load_rules(rules_dir))
    detections = []
    with open(path, encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]
    events.sort(key=lambda e: e["@timestamp"])
    for e in events:
        detections += engine.process(e)
    print(f"replayed {len(events)} events -> {len(detections)} alerts\n")
    for d in detections:
        print(f"  {d.timestamp:%H:%M:%S}  {d.rule.severity.upper():<9}{d.rule.id:<10}{d.rule.title:<58}"
              f"key={d.key or '-':<16}events={len(d.events):<3}{','.join(d.rule.mitre)}")
    sev = Counter(d.rule.severity for d in detections)
    print("\nby severity:", dict(sev))
    return detections


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="minisiem", description="Mini SIEM")
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("rules", help="validate and list detection rules")
    v.add_argument("--dir")
    r = sub.add_parser("replay", help="run rules over a JSON-lines event file")
    r.add_argument("file")
    r.add_argument("--rules")
    s = sub.add_parser("sample", help="write a sample event stream with attack chains")
    s.add_argument("file", nargs="?", default="events.jsonl")
    sv = sub.add_parser("serve", help="start the API")
    sv.add_argument("--db", default="minisiem.db")
    sv.add_argument("--port", type=int, default=8000)
    a = p.parse_args(argv)

    if a.cmd == "rules":
        rules = load_rules(a.dir)
        print(f"{len(rules)} valid rules")
        for rule in rules:
            print(f"  {rule.id:<10}{rule.severity:<10}{rule.type:<11}{rule.title}  [{', '.join(rule.mitre)}]")
    elif a.cmd == "replay":
        replay(a.file, a.rules)
    elif a.cmd == "sample":
        events, _ = generate()
        write_jsonl(a.file, events)
        print(f"wrote {len(events)} events to {Path(a.file).resolve()}")
    else:
        import os

        import uvicorn

        os.environ["MINISIEM_DB"] = a.db
        uvicorn.run("minisiem.api:app", host="127.0.0.1", port=a.port)


if __name__ == "__main__":
    main()
