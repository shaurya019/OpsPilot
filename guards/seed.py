"""Creates the demo SQLite shop database (data/shop.db). Safe to re-run: `python -m opsagent.seed`.

All personal data here is fake. 4111 1111 1111 1111 is a well-known test card number.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from .config import Settings

SCHEMA = """
DROP TABLE IF EXISTS products; DROP TABLE IF EXISTS customers;
DROP TABLE IF EXISTS orders;   DROP TABLE IF EXISTS refunds;
CREATE TABLE products  (id INTEGER PRIMARY KEY, name TEXT, price REAL);
CREATE TABLE customers (id INTEGER PRIMARY KEY, email TEXT, phone TEXT, card_number TEXT, internal_notes TEXT);
CREATE TABLE orders    (id INTEGER PRIMARY KEY, customer_email TEXT, product_id INTEGER,
                        amount REAL, status TEXT);
CREATE TABLE refunds   (id INTEGER PRIMARY KEY AUTOINCREMENT, order_id INTEGER, amount REAL,
                        reason TEXT, requested_by TEXT);
"""


def seed(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.executescript(SCHEMA)
        conn.executemany("INSERT INTO products VALUES (?,?,?)", [
            (1, "Mechanical keyboard", 120.0), (2, "USB-C dock", 640.0), (3, "Mouse pad", 15.0)])
        conn.executemany("INSERT INTO customers VALUES (?,?,?,?,?)", [
            (1, "riya@example.com", "+91 98765 43210", "4111 1111 1111 1111", "VIP, prefers phone"),
            (2, "sam@example.com", "+91 91234 56789", "5500 0000 0000 0004", "Disputed a charge in 2025")])
        conn.executemany("INSERT INTO orders VALUES (?,?,?,?,?)", [
            (1, "riya@example.com", 1, 120.0, "delivered"),
            (2, "sam@example.com", 2, 640.0, "delivered"),
            (3, "riya@example.com", 3, 15.0, "shipped"),
            (4, "sam@example.com", 1, 120.0, "delivered")])


if __name__ == "__main__":
    s = Settings()
    seed(s.sqlite_path)
    print(f"Seeded {s.sqlite_path}")
