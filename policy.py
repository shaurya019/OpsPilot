"""Runtime policy engine.

The LLM *proposes* a tool call; this engine *decides* whether it happens.
It never asks the model for its opinion, so a prompt injection can't talk its
way past it. Think of it as the bank's rules for a cashier: the customer can
say anything, but a withdrawal over the limit needs a manager's signature.

Decision order for a tool call:
  1. Is the tool on the caller's role allowlist?        -> else DENY
  2. First matching tool rule (amount > 500 -> deny ...) -> its decision
  3. Otherwise the tool's default decision
  4. Escalation: session tainted by untrusted content and the tool
     has escalate_when_tainted -> ALLOW becomes REQUIRE_APPROVAL

The policy file is validated with Pydantic (a typo in policy.yaml fails at
startup, not during an incident) and versioned in MongoDB.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from .models import Decision, PolicyDecision

Op = Literal["lt", "le", "gt", "ge", "eq", "ne", "in", "not_in", "contains"]

_OPS = {
    "lt": lambda a, b: a < b,
    "le": lambda a, b: a <= b,
    "gt": lambda a, b: a > b,
    "ge": lambda a, b: a >= b,
    "eq": lambda a, b: a == b,
    "ne": lambda a, b: a != b,
    "in": lambda a, b: a in b,
    "not_in": lambda a, b: a not in b,
    "contains": lambda a, b: b in a,
}


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")   # unknown keys in policy.yaml = error


class BlockedTopic(Strict):
    name: str
    patterns: list[str]


class InputPolicy(Strict):
    max_chars: int = Field(gt=0)
    injection_threshold: int = Field(gt=0)
    block_pii: list[str] = []
    blocked_topics: list[BlockedTopic] = []


class OutputPolicy(Strict):
    max_chars: int = Field(gt=0)
    mask_pii: list[str] = []
    allowed_link_domains: list[str] = []


class ToolOutputPolicy(Strict):
    max_chars: int = Field(gt=0)
    injection_threshold: int = Field(gt=0)
    mask_pii: list[str] = []


class Limits(Strict):
    max_steps: int = Field(gt=0)
    max_tool_calls_per_turn: int = Field(gt=0)
    max_identical_tool_calls: int = Field(gt=0)
    requests_per_minute: int = Field(gt=0)
    daily_token_budget: int = Field(gt=0)


class Rule(Strict):
    field: str
    op: Op
    value: Any
    then: Decision
    reason: str

    def matches(self, args: BaseModel) -> bool:
        if not hasattr(args, self.field):
            return False
        try:
            return bool(_OPS[self.op](getattr(args, self.field), self.value))
        except TypeError:          # e.g. comparing str with int: treat as no match
            return False


class ToolPolicy(Strict):
    default: Decision = Decision.ALLOW
    escalate_when_tainted: bool = False
    rules: list[Rule] = []
    config: dict[str, Any] = {}


class Policy(Strict):
    version: int
    input: InputPolicy
    output: OutputPolicy
    tool_output: ToolOutputPolicy
    limits: Limits
    roles: dict[str, list[str]]
    tools: dict[str, ToolPolicy]

    @classmethod
    def from_yaml(cls, path: Path) -> "Policy":
        return cls.model_validate(yaml.safe_load(path.read_text()))

    def tool_config(self, tool: str) -> dict[str, Any]:
        return self.tools.get(tool, ToolPolicy()).config

    def evaluate(self, tool: str, args: BaseModel, role: str, tainted: bool) -> PolicyDecision:
        if tool not in self.roles.get(role, []):
            return PolicyDecision(decision=Decision.DENY, rule="role_allowlist",
                                  reason=f"Role '{role}' is not allowed to use '{tool}'")
        tool_policy = self.tools.get(tool)
        if tool_policy is None:   # fail closed: a tool without a policy entry is not usable
            return PolicyDecision(decision=Decision.DENY, rule="no_policy", reason=f"No policy for '{tool}'")

        decision = PolicyDecision(decision=tool_policy.default, rule="default",
                                  reason=f"Default for {tool}: {tool_policy.default.value}")
        for i, rule in enumerate(tool_policy.rules):
            if rule.matches(args):
                decision = PolicyDecision(decision=rule.then, rule=f"rules[{i}]", reason=rule.reason)
                break

        if tainted and tool_policy.escalate_when_tainted and decision.decision == Decision.ALLOW:
            decision = PolicyDecision(
                decision=Decision.REQUIRE_APPROVAL, rule="taint_escalation",
                reason="Untrusted content is in this conversation, so a human must confirm this action")
        return decision


class PolicyStore:
    """Keeps every policy version in MongoDB; exactly one is active."""

    def __init__(self, collection):
        self.col = collection

    def activate_from_yaml(self, path: Path) -> Policy:
        raw = path.read_text()
        policy = Policy.model_validate(yaml.safe_load(raw))      # validate BEFORE activating
        digest = hashlib.sha256(raw.encode()).hexdigest()[:16]
        self.col.update_many({"active": True}, {"$set": {"active": False}})
        self.col.update_one({"_id": digest},
                            {"$set": {"active": True, "policy": policy.model_dump(mode="json"), "source": str(path)}},
                            upsert=True)
        return policy

    def active(self) -> Policy:
        doc = self.col.find_one({"active": True})
        if doc is None:
            raise RuntimeError("No active policy in MongoDB. Run the app once or `approver policy-reload`.")
        return Policy.model_validate(doc["policy"])
