"""sql_select: the RISKY way to give an LLM database access (admin role only).

Letting a model write SQL means anything that can steer the model (a user, a
poisoned document) can write SQL too. If you must offer it, use layers:

  1. Validation (a filter): one statement, SELECT only, no comments, only
     allowlisted tables. Easy to read, but string checks can be bypassed.
  2. Read-only connection: SQLite opened with mode=ro, so writes fail.
  3. SQLite authorizer (the wall): the database engine itself asks us about
     every table/column the query touches and we say DENY for anything not on
     the allowlist. This works on the parsed query, so tricks that fool the
     regex still fail here.
  4. Row cap: fetchmany(max_rows) limits how much data can leave.
"""
from __future__ import annotations

import json
import re
import sqlite3

from pydantic import Field

from .base import StrictArgs, Tool, ToolContext, ToolInputError
from .orders import connect_ro

_FORBIDDEN = re.compile(
    r"\b(insert|update|delete|drop|alter|create|replace|attach|detach|pragma|vacuum|reindex|"
    r"load_extension|sqlite_master|sqlite_schema|sqlite_temp_master)\b", re.IGNORECASE)
_TABLE_REF = re.compile(r"\b(?:from|join)\s+([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE)


class SqlSelectArgs(StrictArgs):
    query: str = Field(min_length=10, max_length=500, description="A single read-only SELECT statement")


def validate_select(query: str, allowed_tables: list[str]) -> str:
    q = query.strip().rstrip(";").strip()
    if ";" in q:
        raise ToolInputError("Only one statement is allowed")
    if "--" in q or "/*" in q:
        raise ToolInputError("SQL comments are not allowed")
    if not re.match(r"(?is)^\s*select\b", q):
        raise ToolInputError("Only SELECT statements are allowed")
    if m := _FORBIDDEN.search(q):
        raise ToolInputError(f"Forbidden SQL keyword: {m.group(1)}")
    tables = {t.lower() for t in _TABLE_REF.findall(q)}
    if not tables:
        raise ToolInputError("Query must read from a table")
    if bad := tables - set(allowed_tables):
        raise ToolInputError(f"Tables not allowed: {', '.join(sorted(bad))}")
    return q


def make_authorizer(allowed_tables: list[str]):
    allowed = set(allowed_tables)

    def authorizer(action, arg1, arg2, db_name, trigger):
        if action == sqlite3.SQLITE_SELECT:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_READ:          # arg1 = table, arg2 = column
            return sqlite3.SQLITE_OK if arg1 in allowed else sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_FUNCTION:      # allow ordinary functions like count(), lower()
            return sqlite3.SQLITE_DENY if arg2 in {"load_extension", "readfile", "writefile"} else sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY                 # everything else: no
    return authorizer


class SqlSelectTool(Tool):
    name = "sql_select"
    description = "Run a read-only SELECT on the orders and products tables. Admin only."
    Args = SqlSelectArgs

    def check(self, args: SqlSelectArgs, ctx: ToolContext) -> None:
        validate_select(args.query, ctx.config(self.name).get("allowed_tables", []))

    def run(self, args: SqlSelectArgs, ctx: ToolContext) -> str:
        cfg = ctx.config(self.name)
        query = validate_select(args.query, cfg.get("allowed_tables", []))
        conn = connect_ro(ctx.settings.sqlite_path)
        try:
            conn.set_authorizer(make_authorizer(cfg.get("allowed_tables", [])))
            rows = conn.execute(query).fetchmany(cfg.get("max_rows", 50))
        except sqlite3.DatabaseError as exc:
            raise ToolInputError(f"Query rejected by database: {exc}") from exc
        finally:
            conn.close()
        return json.dumps([dict(r) for r in rows])
