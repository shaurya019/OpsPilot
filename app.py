"""Wires everything together (used by the CLI, the approver and the demo)."""
from __future__ import annotations

from dataclasses import dataclass

from openai import OpenAI

from .agent import GuardedAgent
from .approvals import ApprovalService
from .config import Settings
from .db import Store
from .executor import ToolExecutor
from .guards.input_guard import InputGuard
from .guards.llm_classifier import Classifier, NoopClassifier, OpenAIClassifier
from .guards.output_guard import OutputGuard
from .llm import LLM, OpenAIChat
from .policy import PolicyStore
from .seed import seed
from .tools import Tool, default_tools


@dataclass
class App:
    settings: Settings
    store: Store
    tools: dict[str, Tool]
    approvals: ApprovalService
    agent: GuardedAgent | None


def build_app(settings: Settings | None = None, store: Store | None = None, llm: LLM | None = None,
              classifier: Classifier | None = None, tools: dict[str, Tool] | None = None,
              with_agent: bool = True) -> App:
    settings = settings or Settings()
    store = store or Store.from_settings(settings)
    PolicyStore(store.policies).activate_from_yaml(settings.policy_path)   # validate + version + activate
    if not settings.sqlite_path.exists():
        seed(settings.sqlite_path)

    tools = tools or default_tools()
    approvals = ApprovalService(store, settings.approval_ttl_minutes)
    agent = None
    if with_agent:
        if llm is None or classifier is None:
            if not settings.openai_api_key:
                raise SystemExit("OPENAI_API_KEY is not set. Copy .env.example to .env and add your key.")
            client = OpenAI(api_key=settings.openai_api_key, timeout=30, max_retries=2)
            llm = llm or OpenAIChat(client, settings.model)
            if classifier is None:
                classifier = (OpenAIClassifier(client, settings.classifier_model, settings.moderation_model)
                              if settings.use_llm_classifier else NoopClassifier())
        executor = ToolExecutor(tools, store, approvals, settings)
        agent = GuardedAgent(store, llm, executor,
                             InputGuard(classifier, settings.fail_closed),
                             OutputGuard(classifier, settings.fail_closed))
    return App(settings, store, tools, approvals, agent)
