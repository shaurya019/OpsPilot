"""Text normalization before pattern matching.

Why: attackers dodge keyword filters with look-alike characters
("ignore" typed in full-width Unicode letters), invisible zero-width spaces
("ig<zero-width-space>nore") or leetspeak ("1gn0re"). We match against cleaned-up copies,
but we never change what the user actually sent to the LLM.
"""
from __future__ import annotations

import re
import unicodedata

# Zero-width and other invisible formatting characters.
_INVISIBLE = re.compile("[\\u200b-\\u200f\\u202a-\\u202e\\u2060-\\u2064\\ufeff\\u00ad]")
_WHITESPACE = re.compile(r"[^\S\n]+")  # collapse spaces/tabs, keep line breaks
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def normalize(text: str) -> str:
    """NFKC folds full-width/compatibility characters into plain ones."""
    text = unicodedata.normalize("NFKC", text)
    text = _INVISIBLE.sub("", text)
    return _WHITESPACE.sub(" ", text).strip()


def matching_variants(text: str) -> list[str]:
    """Lower-cased variants to run detectors on: normal and de-leeted."""
    base = normalize(text).lower()
    deleet = base.translate(_LEET)
    return [base] if deleet == base else [base, deleet]


def has_invisible_chars(text: str) -> bool:
    return bool(_INVISIBLE.search(text))
