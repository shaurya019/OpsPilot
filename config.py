"""Settings loaded from environment variables (.env).

Why: secrets (API keys, DB URIs) must never live in code. Everything that can
differ between your laptop, Docker and production comes from the environment.
"""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel, Field

load_dotenv()  # reads .env if present; real environment variables win

BASE_DIR = Path(__file__).resolve().parent.parent


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Settings(BaseModel):
    openai_api_key: str | None = Field(default_factory=lambda: os.getenv("OPENAI_API_KEY"))
    model: str = Field(default_factory=lambda: os.getenv("OPENAI_MODEL", "gpt-5.4-mini"))
    classifier_model: str = Field(
        default_factory=lambda: os.getenv("OPENAI_CLASSIFIER_MODEL", "gpt-5.4-mini")
    )
    moderation_model: str = Field(
        default_factory=lambda: os.getenv("OPENAI_MODERATION_MODEL", "omni-moderation-latest")
    )
    mongo_uri: str = Field(default_factory=lambda: os.getenv("MONGO_URI", "mongodb://localhost:27017"))
    mongo_db: str = Field(default_factory=lambda: os.getenv("MONGO_DB", "guardrails_p1"))
    use_llm_classifier: bool = Field(default_factory=lambda: _env_bool("USE_LLM_CLASSIFIER", True))
    fail_closed: bool = Field(default_factory=lambda: _env_bool("FAIL_CLOSED", True))

    policy_path: Path = BASE_DIR / "policy.yaml"
    kb_dir: Path = BASE_DIR / "data" / "kb"
    sandbox_dir: Path = BASE_DIR / "data" / "sandbox"
    sqlite_path: Path = BASE_DIR / "data" / "shop.db"
    approval_ttl_minutes: int = 30

    def masked_key(self) -> str:
        """Safe to print: never show a full secret, even in debug output."""
        if not self.openai_api_key:
            return "<missing>"
        return self.openai_api_key[:5] + "..." + self.openai_api_key[-4:]
