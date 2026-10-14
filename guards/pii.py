"""PII and secret detection + masking with regular expressions.

Why mask instead of block? In outputs, the answer is usually still useful with
"[EMAIL]" in place of an address. In inputs, some things (card numbers, API
keys) should never be forwarded to a third-party LLM at all, so the input guard
blocks those kinds instead.

Order matters: secrets and card numbers are masked before phone numbers so a
phone regex can't half-match the middle of a card number.

Production note: regexes miss names and addresses. Microsoft Presidio or a
Guardrails AI PII validator (Project 4) add NER-based detection.
"""
from __future__ import annotations

import re
from typing import Callable

# (?i:...) = case-insensitive for that one pattern only (patterns are joined with |)
_SECRET_PATTERNS = [
    r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}",                       # OpenAI-style keys
    r"\bAKIA[0-9A-Z]{16}\b",                                       # AWS access key id
    r"\bgh[pousr]_[A-Za-z0-9]{30,}\b",                             # GitHub tokens
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)",
    r"(?i:\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token)\b\s*[:=]\s*['\"]?[^\s'\"]{6,})",
    r"(?i:\bmongodb(\+srv)?://[^\s:@/]+:[^\s@/]+@\S+)",          # connection string with password
]


def _luhn_ok(number: str) -> bool:
    """Credit cards have a checksum; this cuts false positives on order ids etc."""
    digits = [int(d) for d in number if d.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# kind -> (regex, optional extra check on the matched text)
PII_PATTERNS: dict[str, tuple[re.Pattern, Callable[[str], bool] | None]] = {
    "SECRET": (re.compile("|".join(f"(?:{p})" for p in _SECRET_PATTERNS)), None),
    "CREDIT_CARD": (re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"), _luhn_ok),
    # Aadhaar: 12 digits, first digit 2-9, often grouped 4-4-4. (Real validation uses Verhoeff.)
    "AADHAAR": (re.compile(r"(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)"), None),
    "PAN": (re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"), None),     # Indian PAN card
    "PHONE": (re.compile(r"(?<![\w])(?:\+?91[ -]?)?[6-9]\d{4}[ -]?\d{5}(?!\d)"
                         r"|\+\d{1,3}[ -]?\(?\d{2,4}\)?[ -]?\d{3,4}[ -]?\d{3,4}(?!\d)"), None),
    "EMAIL": (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), None),
}
ORDER = ["SECRET", "CREDIT_CARD", "AADHAAR", "PAN", "PHONE", "EMAIL"]


def find_pii(text: str, kinds: list[str] | None = None) -> list[str]:
    """Return the kinds of PII present (no positions; we only need yes/no per kind)."""
    return mask_pii(text, kinds)[1]


def mask_pii(text: str, kinds: list[str] | None = None,
             keep_email_domains: list[str] | None = None) -> tuple[str, list[str]]:
    """Replace each detected item with [KIND]. Returns (masked_text, kinds_found)."""
    wanted = [k for k in ORDER if kinds is None or k in kinds]
    keep = {d.lower() for d in (keep_email_domains or [])}
    found: list[str] = []

    for kind in wanted:
        regex, check = PII_PATTERNS[kind]

        def repl(m: re.Match, kind=kind, check=check) -> str:
            value = m.group(0)
            if check and not check(value):
                return value
            if kind == "EMAIL" and value.split("@")[-1].lower() in keep:
                return value                     # e.g. our own company addresses are fine
            if kind not in found:
                found.append(kind)
            return f"[{kind}]"

        text = regex.sub(repl, text)
    return text, found
