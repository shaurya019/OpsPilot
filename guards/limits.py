"""Rate limits and token budgets, stored in MongoDB.

Why: an agent in a loop (or an attacker hammering it) burns money and can
amplify damage: 1,000 refund attempts per minute is a different problem than 1.
Counters live in MongoDB so limits hold across processes and restarts, and a
TTL index deletes old windows automatically.

Each counter is one document per (key, time window). `$inc` with `upsert` is
atomic, so two concurrent requests can't both slip under the limit.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from pymongo import ReturnDocument

from .db import Store


class Limiter:
    def __init__(self, store: Store):
        self.counters = store.counters

    def _bump(self, key: str, window_seconds: int, amount: int, now: datetime | None = None) -> int:
        now = now or datetime.now(timezone.utc)
        window_start = int(now.timestamp()) // window_seconds * window_seconds
        doc = self.counters.find_one_and_update(
            {"_id": f"{key}:{window_start}"},
            {"$inc": {"n": amount},
             "$setOnInsert": {"expires_at": now + timedelta(seconds=window_seconds * 2)}},
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        return doc["n"]

    def allow_request(self, user_id: str, per_minute: int) -> bool:
        return self._bump(f"rpm:{user_id}", 60, 1) <= per_minute

    def tokens_used_today(self, user_id: str) -> int:
        return self._bump(f"tokens:{user_id}", 86400, 0)

    def add_tokens(self, user_id: str, tokens: int) -> int:
        return self._bump(f"tokens:{user_id}", 86400, tokens)
