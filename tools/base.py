"""Tool base class.

Every tool declares:
  - Args:   a Pydantic model. extra="forbid" rejects arguments the model invented.
  - trust:  how far we trust what the tool returns
              "trusted"  = our own structured data (DB rows)
              "internal" = text written by many people (KB articles): scanned, wrapped
              "external" = the internet: scanned, wrapped, and taints the session
  - side_effect: True if it changes the world (refund, email). Policy cares about these.
  - check(): semantic validation that types alone can't express
             (path stays inside the sandbox, URL isn't internal, SQL is read-only...)
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, ClassVar, Literal

from pydantic import BaseModel, ConfigDict

from ..config import Settings
from ..db import Store
from ..models import Session
from ..policy import Policy


class ToolInputError(Exception):
    """Raised by Tool.check() when arguments are well-typed but unsafe."""


class StrictArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


@dataclass
class ToolContext:
    user_id: str
    role: str
    policy: Policy
    settings: Settings
    store: Store
    session: Session | None = None

    def config(self, tool: str) -> dict[str, Any]:
        return self.policy.tool_config(tool)


class Tool(ABC):
    name: ClassVar[str]
    description: ClassVar[str]
    Args: ClassVar[type[StrictArgs]]
    trust: ClassVar[Literal["trusted", "internal", "external"]] = "trusted"
    side_effect: ClassVar[bool] = False

    def check(self, args: StrictArgs, ctx: ToolContext) -> None:
        """Override to add semantic validation. Raise ToolInputError to block."""

    @abstractmethod
    def run(self, args: StrictArgs, ctx: ToolContext) -> str: ...

    def openai_schema(self) -> dict:
        """Function-calling schema sent to OpenAI, generated from the Pydantic model."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.Args.model_json_schema(),
            },
        }
