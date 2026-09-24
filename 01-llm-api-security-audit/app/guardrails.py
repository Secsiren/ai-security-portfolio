"""Input and output guardrails for an LLM-backed REST API.

Remediates the three findings in this assessment:
  F1  System prompt exfiltration via delimiter smuggling  (OWASP LLM01 / LLM07)
  F2  Unhandled malformed JSON -> stack trace disclosure  (OWASP API8:2023)
  F3  Unbounded input -> token overflow / resource exhaustion (OWASP API4:2023 / LLM10)

Pattern matching is a defence-in-depth layer, not a complete prompt-injection
defence. The primary controls are role separation (system prompt never
concatenated with user text), strict schema validation and output scanning.
"""
from __future__ import annotations

import re
import unicodedata

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_QUERY_CHARS = 2000

# Known injection / exfiltration phrasings seen during testing (F1).
INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"(output|print|reveal|repeat|show)\s+(the\s+)?(system\s+prompt|instructions\s+above|everything\s+above)",
    r"-{2,}\s*end\s+of\s+system",
    r"\[\s*system\s+(update|override|instruction)",
    r"you\s+are\s+now\s+in\s+(debug|maintenance|developer)\s+mode",
]
_INJECTION_RE = re.compile("|".join(INJECTION_PATTERNS), re.IGNORECASE)


class LLMQueryRequest(BaseModel):
    """Strict request schema: unknown fields rejected, types and sizes bounded (F2, F3)."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    session_id: str = Field(..., pattern=r"^[A-Za-z0-9\-]{8,36}$")
    query: str = Field(..., min_length=1, max_length=MAX_QUERY_CHARS)
    temperature: float = Field(default=0.7, ge=0.0, le=1.0)

    @field_validator("query")
    @classmethod
    def reject_control_chars_and_injection(cls, value: str) -> str:
        # Null bytes / control characters were used to break the parser (F2).
        if any(unicodedata.category(ch) == "Cc" and ch not in "\n\t" for ch in value):
            raise ValueError("query contains control characters")
        # Normalise look-alike characters before matching (F1).
        normalised = unicodedata.normalize("NFKC", value)
        if _INJECTION_RE.search(normalised):
            raise ValueError("query matches a blocked prompt-injection pattern")
        return value


def scan_output_for_leakage(output_text: str, protected_fragments: list[str]) -> str:
    """Post-generation check: never return text that echoes protected system-prompt fragments (F1).

    `protected_fragments` should be distinctive substrings of the system prompt
    (canary tokens work well). Comparison is case-insensitive and whitespace-normalised.
    """
    def _norm(s: str) -> str:
        return re.sub(r"\s+", " ", unicodedata.normalize("NFKC", s)).strip().lower()

    haystack = _norm(output_text)
    for fragment in protected_fragments:
        if fragment and _norm(fragment) in haystack:
            return "Response withheld by security policy."
    return output_text
