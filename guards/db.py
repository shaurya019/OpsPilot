"""MongoDB access: audit log, approvals, rate/budget counters, policies, outbox.

Every security decision is written to `audit_logs`. If you can't answer
"what did the agent try to do, and who/what stopped it?" after an incident,
your guardrails are only half done.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pymongo import ASCENDING, MongoClient
from pymongo.database import Database

from .config import Settings
from .guards.pii import mask_pii

# Free-text fields are masked before they are stored, so the audit log itself
# does not become a pile of secrets and personal data.
_TEXT_FIELDS = {"text", "args", "output", "reason", "note"}
_AUDIT_MASK = ["SECRET", "CREDIT_CARD", "AADHAAR", "PAN", "PHONE"]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _mask_value(value: Any) -> Any:
    if isinstance(value, str):
        return mask_pii(value, _AUDIT_MASK)[0]
    if isinstance(value, dict):
        return {k: _mask_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_mask_value(v) for v in value]
    return value


class Store:
    def __init__(self, db: Database):
        self.db = db
        self.audit_logs = db["audit_logs"]
        self.approvals = db["approvals"]
        self.counters = db["counters"]
        self.policies = db["policies"]
        self.outbox = db["outbox"]          # "sent" emails (simulated)

    @classmethod
    def from_settings(cls, settings: Settings) -> "Store":
        client = MongoClient(settings.mongo_uri, serverSelectionTimeoutMS=3000)
        client.admin.command("ping")        # fail fast with a clear error if Mongo is down
        store = cls(client[settings.mongo_db])
        store.ensure_indexes()
        return store

    def ensure_indexes(self) -> None:
        # Counters delete themselves after their window ends (TTL index).
        self.counters.create_index("expires_at", expireAfterSeconds=0)
        self.audit_logs.create_index([("ts", ASCENDING)])
        self.audit_logs.create_index([("session_id", ASCENDING)])
        self.approvals.create_index([("status", ASCENDING), ("created_at", ASCENDING)])

    def audit(self, event: str, **fields: Any) -> None:
        doc = {"ts": utcnow(), "event": event}
        for key, value in fields.items():
            doc[key] = _mask_value(value) if key in _TEXT_FIELDS else value
        self.audit_logs.insert_one(doc)
