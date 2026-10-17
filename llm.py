"""Thin wrapper around OpenAI chat completions with tool calling.

Keeping the LLM behind a tiny interface lets the tests swap in a ScriptedLLM,
so every guardrail can be tested offline and deterministically.

API reference: https://platform.openai.com/docs/guides/function-calling
(If OpenAI changes parameter names, this is the only file to update.)
"""
from __future__ import annotations

from typing import Protocol

from openai import OpenAI
from pydantic import BaseModel


class ToolCall(BaseModel):
    id: str
    name: str
    arguments: str

class LLMResponse(BaseModel):
    content: str | None = None
    tool_calls: list[ToolCall] = []
    total_tokens: int = 0
    
    def as_message(self) -> dict:
        """The assistant message to append to history (OpenAI format)."""
        msg: dict = {"role": "assistant", "content": self.content}
        if self.tool_calls:
            msg["tool_calls"] = [
               {"id": c.id, "type": "function", "function": {"name": c.name, "arguments": c.arguments}}
                for c in self.tool_calls
            ]
        return msg
    
class LLM(Protocol):
    def complete(self, messages: list[dict], tools: list[dict]) -> LLMResponse: ...

class OpenAIChat:
    def __init__(self, client: OpenAI, model: str, max_completion_tokens: int = 1200):
        self.client = client
        self.model = model
        self.max_completion_tokens = max_completion_tokens 
        
    def complete(self,messages,tools)-> LLMResponse:
        kwargs: dict = {"model": self.model, "messages": messages,
                        "max_completion_tokens": self.max_completion_tokens}
        
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        
        res = self.client.chat.completions.create(**kwargs)
        msg = res.choices[0].message
        
        calls = [
            ToolCall(id=c.id, name=c.function.name, arguments=c.function.arguments or "{}")
            for c in (msg.tool_calls or []) if c.type == "function"
        ]
        return LLMResponse(content=msg.content, tool_calls=calls,
                           total_tokens=resp.usage.total_tokens if resp.usage else 0)

class ScriptedLLM:
    """Test double: returns pre-written responses in order and records what it was sent."""

    def __init__(self, responses: list[LLMResponse]):
        self.responses = list(responses)
        self.calls: list[list[dict]] = []

    def complete(self, messages: list[dict], tools: list[dict]) -> LLMResponse:
        self.calls.append([dict(m) for m in messages])
        self.last_tools = tools
        if not self.responses:
            return LLMResponse(content="(no more scripted responses)")
        return self.responses.pop(0)