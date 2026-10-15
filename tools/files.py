"""read_file: read a note from the sandbox folder (data/sandbox).

File-system restriction ("jail"): the model gives us a path; we resolve it to
an absolute path and check it is still inside the sandbox. This defeats
"../../secrets/prod.env", absolute paths and symlinks that point outside,
because resolve() follows symlinks before we compare.

Analogy: a hotel key card that opens your room, not every door in the building.
"""
from __future__ import annotations

from pathlib import Path

from pydantic import Field

from .base import StrictArgs, Tool, ToolContext, ToolInputError


class ReadFileArgs(StrictArgs):
    path: str = Field(min_length=1, max_length=200, description="Path relative to the notes sandbox, e.g. notes/runbook.md")


def resolve_in_sandbox(sandbox: Path, user_path: str, allowed_ext: list[str]) -> Path:
    if "\x00" in user_path:
        raise ToolInputError("Null byte in path")
    candidate = Path(user_path)
    if candidate.is_absolute():
        raise ToolInputError("Absolute paths are not allowed")
    if any(part.startswith(".") and part not in {".", ".."} for part in candidate.parts):
        raise ToolInputError("Hidden files (like .env) are not allowed")
    root = sandbox.resolve()
    target = (root / candidate).resolve()          # follows symlinks and ".."
    if not target.is_relative_to(root):
        raise ToolInputError("Path escapes the sandbox")
    if target.suffix.lower() not in allowed_ext:
        raise ToolInputError(f"File type {target.suffix or '(none)'} is not allowed")
    if not target.is_file():
        raise ToolInputError("File not found")
    return target


class ReadFileTool(Tool):
    name = "read_file"
    description = "Read an internal note or runbook from the notes sandbox. Use paths like notes/runbook.md."
    Args = ReadFileArgs
    trust = "internal"

    def check(self, args: ReadFileArgs, ctx: ToolContext) -> None:
        cfg = ctx.config(self.name)
        target = resolve_in_sandbox(ctx.settings.sandbox_dir, args.path, cfg.get("allowed_extensions", [".md"]))
        if target.stat().st_size > cfg.get("max_bytes", 65536):
            raise ToolInputError("File too large")

    def run(self, args: ReadFileArgs, ctx: ToolContext) -> str:
        cfg = ctx.config(self.name)
        target = resolve_in_sandbox(ctx.settings.sandbox_dir, args.path, cfg.get("allowed_extensions", [".md"]))
        return target.read_text(encoding="utf-8", errors="replace")
