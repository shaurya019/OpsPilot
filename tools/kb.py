"""search_kb: keyword search over Markdown articles in data/kb.

Trust level "internal": many employees can edit KB pages, so one of them (or a
compromised account) can plant instructions for the AI. This is the classic
*indirect* prompt injection: the attacker never talks to the agent directly.
"""
from __future__ import annotations

import re

from pydantic import Field

from .base import StrictArgs, Tool, ToolContext


class SearchKbArgs(StrictArgs):
    query: str = Field(min_length=2, max_length=200, description="Keywords to search for")


class SearchKbTool(Tool):
    name = "search_kb"
    description = "Search Acme Shop's internal knowledge base (policies, FAQs). Returns the best matching articles."
    Args = SearchKbArgs
    trust = "internal"

    def run(self, args: SearchKbArgs, ctx: ToolContext) -> str:
        words = {w for w in re.findall(r"[a-z0-9]+", args.query.lower()) if len(w) > 2}
        scored = []
        for path in sorted(ctx.settings.kb_dir.glob("*.md")):
            body = path.read_text(encoding="utf-8")
            score = sum(body.lower().count(w) for w in words)
            if score:
                scored.append((score, path.name, body))
        if not scored:
            return "No matching articles."
        scored.sort(reverse=True)
        return "\n\n".join(f"### {name}\n{body}" for _, name, body in scored[:2])
