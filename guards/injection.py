"""Heuristic prompt-injection / jailbreak detector.

How it works: a list of weighted regex patterns. Each match adds its weight to
a score; the caller blocks when score >= threshold. Weights let weak signals
("the assistant should...") count only when combined with others.

Honest limits: regexes catch the lazy 80% (copy-pasted "ignore previous
instructions", DAN prompts, fake <system> tags). Paraphrases and other
languages get through, which is why an LLM classifier runs after this, and why
tools are locked down regardless of what the model is convinced to do.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .normalize import has_invisible_chars, matching_variants

PATTERNS: list[tuple[str, str, int]] = [
    ("override_instructions",
     r"\b(ignore|disregard|forget|override|bypass)\b.{0,40}\b(previous|prior|above|earlier|all|your|system|the)\b"
     r".{0,20}\b(instructions?|rules|prompts?|guidelines|directives)\b", 3),
    ("reveal_system_prompt",
     r"\b(reveal|show|print|repeat|output|leak|tell me|what is|what's)\b.{0,30}\b(system prompt|hidden (prompt|instructions)"
     r"|initial instructions|your instructions|developer message|your prompt)\b", 3),
    ("jailbreak_persona", r"\b(dan|do anything now|developer mode|jailbreak|jailbroken|god mode)\b", 3),
    ("role_hijack", r"\byou are (now|no longer)\b|\bfrom now on,? you\b|\bact as (an? )?(unrestricted|unfiltered|evil)\b", 2),
    ("no_rules", r"\b(no|without|free of|ignore) (any |all )?(restrictions|filters|rules|limits|guidelines|censorship)\b", 2),
    ("hypothetical_bypass",
     r"\b(pretend|imagine|roleplay|role-play|hypothetically)\b.{0,50}\b(no rules|not bound|allowed to|unrestricted)\b", 2),
    ("fake_role_marker", r"(<\|?/?(system|im_start|im_end)\|?>|\[/?inst\]|^#{1,3} ?(system|new instructions)\b|^\s*system\s*:)", 2),
    ("new_instructions", r"\b(new|updated|important|urgent|real) (instructions?|task|directive)s?\s*:", 2),
    ("exfil_instruction",
     r"\b(send|email|forward|post|upload|exfiltrate)\b.{0,60}\b(to|at)\b\s*(https?://|[\w.+-]+@[\w-]+\.)", 2),
    ("agent_directed", r"\b(ai|assistant|agent|llm|chatbot|model)s?\b.{0,30}\b(must|should|need to|is instructed to)\b", 1),
]

_COMPILED = [(name, re.compile(pattern, re.MULTILINE), weight) for name, pattern, weight in PATTERNS]

@dataclass
class InjectionScan:
    score: int = 0
    matches: list[str] = field(default_factory=list)
    
    def is_attack(self, threshold: int) -> bool:
        return self.score >= threshold
    
def scan_injection(text: str) -> InjectionScan:
    res = InjectionScan()
    for name,regex,weight in _COMPILED:
        if any(regex.search(variant) for variant in matching_variants(text)):
            res.score += weight
            res.matches.append(name)
    if has_invisible_chars(text):
        res.score += 1
        res.matches.append("invisible_chars")
    return res