"""Human-in-the-loop approvals, stored in MongoDB.

Design rules (each one closes a real hole):
  - The approver approves an exact, frozen set of arguments. On approval we
    execute THOSE stored arguments, not whatever the model says next
    (no swapping "refund 60" for "refund 6000" after the human said yes).
  - Approval is single-use and atomic: the status moves pending -> approved
    with one find_one_and_update, so a double-click can't run it twice.
  - Requests expire (default 30 min). Stale context = stale approval.
  - Separation of duties: the person who asked can't approve their own request.
  - Before executing, arguments are re-validated (the order may have been
    refunded in the meantime) and the role allowlist is re-checked.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import timedelta
from typing import TYPE_CHECKING

from pymongo import ReturnDocument

from .db import Store, utcnow
from .models import Session
from .policy import Policy

if TYPE_CHECKING:
    from .tools.base import Tool


class ApprovalError(Exception):
    pass


class ApprovalService:
    def __init__(self, store: Store, ttl_minutes: int = 30):
        self.store = store
        self.col = store.approvals
        self.ttl = timedelta(minutes=ttl_minutes)

    def create(self, session: Session, tool: str, args: dict, reason: str) -> str:
        approval_id = uuid.uuid4().hex[:8]
        now = utcnow()
        self.col.insert_one({
            "_id": approval_id,
            "status": "pending",
            "tool": tool,
            "args": args,
            "args_hash": hashlib.sha256(json.dumps(args, sort_keys=True).encode()).hexdigest(),
            "reason": reason,
            "requested_by": session.user_id,
            "role": session.role,
            "session_id": session.id,
            "tainted": session.tainted,
            "taint_reasons": session.taint_reasons,
            "created_at": now,
            "expires_at": now + self.ttl,
        })
        self.store.audit("approval.created", approval_id=approval_id, tool=tool, args=args,
                         session_id=session.id, user_id=session.user_id)
        return approval_id

    def pending(self) -> list[dict]:
        return list(self.col.find({"status": "pending", "expires_at": {"$gt": utcnow()}}).sort("created_at", 1))

    def decide(self, approval_id: str, approver: str, approve: bool, note: str,
               tools: dict[str, "Tool"], policy: Policy, settings) -> str:
        doc = self.col.find_one({"_id": approval_id})
        if doc is None:
            raise ApprovalError("No such approval")
        if doc["requested_by"] == approver:
            raise ApprovalError("You cannot approve your own request (separation of duties)")

        # Atomic state change: only succeeds if still pending and not expired.
        doc = self.col.find_one_and_update(
            {"_id": approval_id, "status": "pending", "expires_at": {"$gt": utcnow()}},
            {"$set": {"status": "approved" if approve else "denied", "decided_by": approver,
                      "decided_at": utcnow(), "note": note}},
            return_document=ReturnDocument.AFTER,
        )
        if doc is None:
            raise ApprovalError("Approval is not pending anymore (already decided or expired)")
        self.store.audit("approval.decided", approval_id=approval_id, approved=approve,
                         decided_by=approver, note=note)
        if not approve:
            return "Denied."
        return self._execute(doc, tools, policy, settings)

    def _execute(self, doc: dict, tools: dict[str, "Tool"], policy: Policy, settings) -> str:
        from .tools.base import ToolContext, ToolInputError

        tool = tools[doc["tool"]]
        if doc["tool"] not in policy.roles.get(doc["role"], []):
            result, status = "Requester's role no longer allows this tool.", "failed"
        else:
            ctx = ToolContext(user_id=doc["requested_by"], role=doc["role"], policy=policy,
                              settings=settings, store=self.store)
            try:
                args = tool.Args.model_validate(doc["args"])     # the frozen, approved arguments
                tool.check(args, ctx)                            # state may have changed since
                result, status = tool.run(args, ctx), "executed"
            except (ToolInputError, ValueError) as exc:
                result, status = f"Not executed: {exc}", "failed"
        self.col.update_one({"_id": doc["_id"]}, {"$set": {"status": status, "result": result}})
        self.store.audit("approval.executed", approval_id=doc["_id"], status=status, output=result)
        return result
