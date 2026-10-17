"""Guarded tool executor: every tool call the LLM proposes goes through here.

    LLM proposes call(name, json_args)
        |
        1. tool exists + role allows it?   no -> BLOCKED
        2. JSON parses + Pydantic Args     no -> ERROR (invalid arguments)
        3. tool.check()  (sandbox, SSRF,   no -> BLOCKED (unsafe input)
           SQL, recipients, DLP)
        4. turn limits (count, loops)      no -> BLOCKED (limit)
        5. policy.evaluate()               deny -> BLOCKED
                                           require_approval -> PENDING (stored in MongoDB)
        6. tool.run()                      exception -> ERROR (no stack trace to the model)
        7. validate_tool_output()          mask, scan, quarantine, wrap as untrusted data
        |
    result string goes back to the LLM

Steps 2-3 run BEFORE the policy so a human is never asked to approve an
obviously malicious call (e.g. an SSRF URL).

Every outcome is audited. Messages returned to the model are short and
factual: they tell it what happened without leaking internals.
"""
from __future__ import annotations

import json
from collections import Counter

from pydantic import ValidationError

from .approvals import ApprovalService
from .guards.db import Store
from .guards.output_guard import validate_tool_output
from .models import Decision, Session
from .policy import Policy
from .tools.base import Tool, ToolContext, ToolInputError


class TurnState:
    """Counters that reset with each user message."""

    def __init__(self) -> None:
        self.calls = 0
        self.signatures: Counter[str] = Counter()
        self.pending: list[str] = []
        
class ToolExecutor:
    def __init__(self, tools: dict[str, Tool], store: Store, approvals: ApprovalService, settings):
        self.tools = tools
        self.store = store
        self.approvals = approvals
        self.settings = settings
        
    def schemas_for(self, role: str, policy: Policy) -> list[dict]:
        """Least privilege starts here: the model only SEES tools its user's role may use."""
        allowed = set(policy.roles.get(role, []))
        return [t.openai_schema() for name, t in self.tools.items() if name in allowed]
    
    def execute(self, name: str, raw_args: str, session: Session, policy: Policy, turn: TurnState) -> str:
        audit = lambda event, **kw: self.store.audit(event, session_id=session.id, user_id=session.user_id,
                                                      tool=name, **kw)
        
        # 1. Unknown tool
        # tool and role checks: Blocks calls to nonexistent tools or tools the user’s role isn’t allowed to use.
        tool = self.tools.get(tool)
        if tool is None:
            audit("tool.blocked", reason="unknown tool")
            return f"BLOCKED: tool '{name}' does not exist."
        
         # The model only saw tools its role allows, but it can still *name* others
        # (hallucination or injection). Check again: never trust the model's choice.
        if name not in policy.roles.get(session.role, []):
            audit("tool.blocked", reason="role allowlist")
            return f"BLOCKED by policy: role '{session.role}' may not use '{name}'."


        # 2. Parse and validate argument types
        # Parses the JSON and validates it against that tool’s argument schema. If that fails, it audits the issue and returns an ERROR.
        try:
            args = tool.Args.model_validate(json.loads(raw_args or "{}"))
        except (json.JSONDecodeError, ValidationError) as exc:
            errors = exc.errors(include_url=False) if isinstance(exc, ValidationError) else [{"msg": "invalid JSON"}]
            summary = "; ".join(f"{'.'.join(map(str, e.get('loc', [])))}: {e['msg']}" for e in errors)[:300]
            audit("tool.invalid_args", reason=summary, args=raw_args[:500])
            return f"ERROR: invalid arguments for {name}: {summary}"
        
        ctx = ToolContext(user_id=session.user_id, role=session.role, policy=policy,
                          settings=self.settings, store=self.store, session=session)
        # 3. Semantic input validation
        # Builds a context for the tool, then calls tool.check(...) for tool-specific checks. Unsafe arguments are audited and returned as BLOCKED.
        try:
            tool.check(args, ctx)
        except ToolInputError as exc:
            audit("tool.blocked", reason=str(exc), args=args.model_dump(mode="json"))
            return f"BLOCKED: {exc}"
        
        # 4. Per-turn limits: total calls and identical-call loops
        # Counts calls and tracks repeated identical calls. It blocks calls that exceed the policy’s call limit or repeat-call limit.
        turn.calls += 1
        signature = name + json.dumps(args.model_dump(mode="json"), sort_keys=True)
        turn.signatures[signature] += 1
        if turn.calls > policy.limits.max_tool_calls_per_turn:
            audit("tool.blocked", reason="tool call limit")
            return "BLOCKED: tool call limit for this message reached. Answer with what you have."
        if turn.signatures[signature] > policy.limits.max_identical_tool_calls:
            audit("tool.blocked", reason="repeated identical call")
            return "BLOCKED: this exact call was already made. Do not repeat it."
        
        # 5. Runtime policy
        # Records the policy decision. A DENY returns BLOCKED; REQUIRE_APPROVAL saves the validated arguments as an approval request, adds its ID to the turn state, and returns PENDING_APPROVAL. The action hasn’t run yet.
        decision = policy.evaluate(name, args, session.role, session.tainted)
        audit("policy.decision", decision=decision.decision.value, rule=decision.rule,
              reason=decision.reason, args=args.model_dump(mode="json"))
        if decision.decision == Decision.DENY:
            return f"BLOCKED by policy: {decision.reason}"
        if decision.decision == Decision.REQUIRE_APPROVAL:
            approval_id = self.approvals.create(session, name, args.model_dump(mode="json"), decision.reason)
            turn.pending.append(approval_id)
            return (f"PENDING_APPROVAL id={approval_id}: {decision.reason}. The action has NOT been done yet. "
                    "Tell the user it is waiting for human approval.")
        
        # 6. Run
        # Runs the tool when policy allows it. A ToolInputError becomes BLOCKED. Other exceptions are audited and returned as a short ERROR, without giving the LLM a stack trace.
        try:
            raw = tool.run(args, ctx)
        except ToolInputError as exc:
            audit("tool.blocked", reason=str(exc))
            return f"BLOCKED: {exc}"
        except Exception as exc:  # never hand stack traces / internals to the model
            audit("tool.error", reason=f"{type(exc).__name__}: {exc}")
            return f"ERROR: {name} failed ({type(exc).__name__})."

        # 7. Validate output before it re-enters the model's context
        text, findings = validate_tool_output(name, tool.trust, raw, session, policy)
        audit("tool.ok", findings=findings, tainted=session.tainted)
        return text