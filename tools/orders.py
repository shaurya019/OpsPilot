"""Order tools backed by the SQLite "shop" database (data/shop.db).

get_order     - the SAFE way to give an LLM database access: one narrow tool,
                typed arguments, parameterized query. There is no SQL string
                for an attacker to inject into.
issue_refund  - a side-effecting tool. Pydantic bounds the amount, check()
                verifies it against the real order, and the policy engine
                decides allow / approval / deny.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from pydantic import Field

from .base import StrictArgs, Tool, ToolContext, ToolInputError


def connect_ro(path: Path) -> sqlite3.Connection:
    """Read-only connection: even a bug in our code can't write through it."""
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def connect_rw(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn

class GetOrderArgs(StrictArgs):
    order_id: int = Field(gt=0, lt=10_000_000, description="Numeric order id")
    
class IssueRefundArgs(StrictArgs):
    order_id: int = Field(gt=0, lt=10_000_000)
    amount: float = Field(gt=0, le=10_000, description="Refund amount in USD")
    reason: str = Field(min_length=5, max_length=200)

class GetOrderTool(Tool):
    name = "get_order"
    description = "Look up one order by its numeric id (status, amount, product)."
    Args = GetOrderArgs
    
    def run(self, args: GetOrderArgs, ctx: ToolContext) -> str:
        with connect_ro(ctx.settings.sqlite_path) as conn:
            row = conn.execute(
                 "SELECT o.id, o.status, o.amount, o.customer_email, p.name AS product "
                "FROM orders o JOIN products p ON p.id = o.product_id WHERE o.id = ?",
                (args.order_id,),
            ).fetchone()
        return json.dumps(dict(row)) if row else f"Order {args.order_id} not found."
    
class IssueRefundTool(Tool):
    name = "issue_refund"
    description = ("Refund (part of) an order. Small refunds run immediately; larger ones are sent "
                   "to a human for approval.")
    Args = IssueRefundArgs
    side_effect = True
    
    def check(self, args: IssueRefundArgs, ctx: ToolContext) -> None:
        with connect_ro(ctx.settings.sqlite_path) as conn:
            row = conn.execute("SELECT amount, status FROM orders WHERE id = ?", (args.order_id,)).fetchone()
        if row is None:
            raise ToolInputError(f"Order {args.order_id} does not exist")
        if row["status"] == "refunded":
            raise ToolInputError("Order is already refunded")
        if args.amount > row["amount"]:
            raise ToolInputError(f"Refund {args.amount} exceeds order total {row['amount']}")
        
    
    def run(self, args: IssueRefundArgs, ctx: ToolContext) -> str:
        with connect_rw(ctx.settings.sqlite_path) as conn:
            conn.execute("UPDATE orders SET status = 'refunded' WHERE id = ?", (args.order_id,))
            conn.execute("INSERT INTO refunds (order_id, amount, reason, requested_by) VALUES (?, ?, ?, ?)",
                         (args.order_id, args.amount, args.reason, ctx.user_id))
        return f"Refunded {args.amount:.2f} USD for order {args.order_id}."