"""Input guardrail: runs on every user message BEFORE it reaches the LLM.

Checks run cheapest-first and stop at the first failure:
  1. empty / too long             (free, catches prompt-stuffing)
  2. blocked business topics      (regex)
  3. prompt-injection heuristics  (regex + scoring)
  4. sensitive data in the input  (cards, Aadhaar, API keys must not go to the LLM provider)
  5. OpenAI moderation            (harmful content)
  6. LLM classifier               (paraphrased injection, jailbreak, off-topic)

Why cheapest-first: most traffic is benign and the regex checks cost
microseconds; we only pay for an LLM call when the cheap layers found nothing.
"""
from __future__ import annotations

import re

from ..models import GuardResult
from ..policy import Policy
from .injection import scan_injection
from .llm_classifier import Classifier, NoopClassifier
from .normalize import matching_variants
from .pii import find_pii

CLASSIFIER_MIN_CONFIDENCE = 0.7


class InputGuard:
    def __init__(self, classifier: Classifier | None = None, fail_closed: bool = True):
        self.classifier = classifier or NoopClassifier()
        self.fail_closed = fail_closed

    def check(self, text: str, policy: Policy) -> GuardResult:
        cfg = policy.input

        # 1. Size limits
        if not text or not text.strip():
            return GuardResult(allowed=False, guard="input.empty", reason="Empty message")
        if len(text) > cfg.max_chars:
            return GuardResult(allowed=False, guard="input.length",
                               reason=f"Message is {len(text)} chars; limit is {cfg.max_chars}")

        # 2. Blocked topics (business policy, not security)
        variants = matching_variants(text)
        for topic in cfg.blocked_topics:
            for pattern in topic.patterns:
                if any(re.search(pattern, v) for v in variants):
                    return GuardResult(allowed=False, guard="input.blocked_topic",
                                       reason=f"Topic not supported: {topic.name}", findings=[topic.name])

        # 3. Prompt injection / jailbreak heuristics
        scan = scan_injection(text)
        if scan.is_attack(cfg.injection_threshold):
            return GuardResult(allowed=False, guard="input.injection",
                               reason=f"Prompt-injection patterns (score {scan.score})", findings=scan.matches)

        # 4. Sensitive data that must never be sent to the LLM provider
        pii = find_pii(text, cfg.block_pii)
        if pii:
            return GuardResult(allowed=False, guard="input.sensitive_data",
                               reason="Please remove sensitive data (" + ", ".join(pii) + ") and try again",
                               findings=pii)

        # 5 + 6. Model-based checks
        try:
            flagged = self.classifier.moderate(text)
            if flagged:
                return GuardResult(allowed=False, guard="input.moderation",
                                   reason="Content flagged by moderation", findings=flagged)
            verdict = self.classifier.classify(text, stage="input")
            if verdict.category != "safe" and verdict.confidence >= CLASSIFIER_MIN_CONFIDENCE:
                return GuardResult(allowed=False, guard="input.llm_classifier",
                                   reason=f"{verdict.category}: {verdict.reason}", findings=[verdict.category])
        except Exception as exc:  # network error, rate limit, bad key...
            if self.fail_closed:
                return GuardResult(allowed=False, guard="input.classifier_error",
                                   reason=f"Safety check unavailable ({type(exc).__name__}); failing closed")

        return GuardResult(allowed=True, guard="input", text=text,
                           findings=scan.matches)  # weak signals are kept for the audit log
