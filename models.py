"""Small shared data models used across guards, policy and agent."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import secrets
import uuid

from pydantic import BaseModel

class Decision(str,Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"

class GuardResult(BaseModel):
    """What every guard returns. `text` is the (possibly modified, e.g. masked) text."""
    
    allowed:bool
    guard: str
    reason: str = ""
    text: str | None = None
    findings: list[str] = []
    
class PolicyDecision(BaseModel):
    decision: Decision
    reason: str
    rule: str = ""
    
class AgentReply(BaseModel):
    text: str
    blocked: bool = False
    blocked_by: str | None = None
    pending_approvals: list[str] = []
    steps: int = 0

@dataclass
class Session:
    """One conversation. `tainted` flips to True once untrusted data entered the context."""

    user_id: str
    role: str
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    tainted: bool = False
    taint_reasons: list[str] = field(default_factory=list)
    messages: list[dict] = field(default_factory=list)
    canary: str = field(default_factory=lambda: "CANARY-" + secrets.token_hex(6))
    
    def taint(self, reason: str) -> None:
        self.tainted = True
        if reason not in self.taint_reasons:
            self.taint_reasons.append(reason)