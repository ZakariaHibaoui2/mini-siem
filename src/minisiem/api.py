"""SIEM REST API (FastAPI)."""
from __future__ import annotations

import os
import threading
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from . import __version__
from .engine import Engine, load_rules
from .store import STATUSES, Store


class AlertUpdate(BaseModel):
    status: str
    note: str | None = None


def create_app(db_path: str = ":memory:", rules_dir: str | None = None, api_key: str | None = None) -> FastAPI:
    rules = load_rules(rules_dir)
    engine = Engine(rules)
    store = Store(db_path)
    lock = threading.Lock()
    app = FastAPI(title="Mini SIEM", version=__version__)

    def auth(x_api_key: str | None = Header(default=None)) -> None:
        if api_key and x_api_key != api_key:
            raise HTTPException(401, "invalid API key")

    def ingest_one(event: dict[str, Any]) -> list[int]:
        event.setdefault("@timestamp", datetime.now(timezone.utc).isoformat())
        try:
            with lock:  # detection state is order-sensitive
                dets = engine.process(event)
        except (ValueError, TypeError) as exc:
            raise HTTPException(422, f"bad event: {exc}") from exc
        store.add_event(event)
        return [store.add_alert(d) for d in dets]

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__, "rules": len(rules)}

    @app.post("/ingest", dependencies=[Depends(auth)])
    def ingest(event: dict[str, Any]) -> dict:
        return {"alerts": ingest_one(event)}

    @app.post("/ingest/batch", dependencies=[Depends(auth)])
    def ingest_batch(events: list[dict[str, Any]]) -> dict:
        if len(events) > 5000:
            raise HTTPException(413, "max 5000 events per batch")
        new = [a for e in events for a in ingest_one(e)]
        return {"ingested": len(events), "alerts": new}

    @app.get("/alerts", dependencies=[Depends(auth)])
    def list_alerts(status: str | None = None, severity: str | None = None, limit: int = 200) -> list[dict]:
        return store.alerts(status, severity, min(limit, 1000))

    @app.patch("/alerts/{alert_id}", dependencies=[Depends(auth)])
    def update_alert(alert_id: int, body: AlertUpdate) -> dict:
        if body.status not in STATUSES:
            raise HTTPException(422, f"status must be one of {STATUSES}")
        if not store.update_alert(alert_id, body.status, body.note):
            raise HTTPException(404, "alert not found")
        return {"id": alert_id, "status": body.status}

    @app.get("/rules", dependencies=[Depends(auth)])
    def list_rules() -> list[dict]:
        return [{"id": r.id, "title": r.title, "severity": r.severity, "type": r.type, "mitre": r.mitre}
                for r in rules]

    @app.get("/stats", dependencies=[Depends(auth)])
    def stats() -> dict:
        return store.stats()

    return app


app = create_app(os.environ.get("MINISIEM_DB", ":memory:"), os.environ.get("MINISIEM_RULES"),
                 os.environ.get("MINISIEM_API_KEY"))
