"""Defence-in-depth controls for a RAG assistant with tool-calling.

Mitigates the assessment findings:
  S-A  Indirect prompt injection via poisoned documents   (ATLAS AML.T0051.001, AML.T0070; OWASP LLM01)
  S-A  Render-time data exfiltration via markdown images  (ATLAS AML.T0057; OWASP LLM02/LLM05)
  S-B  Encoded (Base64) jailbreak payloads                 (ATLAS AML.T0054; OWASP LLM01)
  S-C  Excessive agency: destructive SQL via tool calls    (ATLAS AML.T0053; OWASP LLM06)
"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

# --- S-A: retrieved-context sanitisation ---------------------------------

_CONTEXT_INJECTION = re.compile(
    r"(\[\s*system\s+(instruction|override|update)[^\]]*\]"
    r"|-{2,}\s*end\s+of\s+system[^\n]*"
    r"|ignore\s+(all\s+)?(previous|prior)\s+(summari[sz]ation\s+)?(directives|instructions)"
    r"|ai\s+assistant\s*:\s*[^\n]*call\s+tool)",
    re.IGNORECASE,
)


def sanitize_retrieved_context(chunk: str) -> tuple[str, bool]:
    """Neutralise instruction-like text in a retrieved chunk.

    Returns (cleaned_text, flagged). Flagged chunks should be logged and ideally
    quarantined for review; the document source should be treated as untrusted.
    """
    cleaned, n = _CONTEXT_INJECTION.subn("[FILTERED]", chunk)
    return cleaned, n > 0


def wrap_context(chunks: list[str]) -> str:
    """Delimit retrieved data so the system prompt can state it is data, never instructions."""
    body = "\n\n".join(chunks).replace("</retrieved_context>", "")
    return f"<retrieved_context>\n{body}\n</retrieved_context>"


# --- S-A: output sanitisation against render-time exfiltration ----------

_MD_IMAGE = re.compile(r"!\[([^\]]*)\]\(\s*<?([^)\s>]+)>?[^)]*\)")
_MD_LINK = re.compile(r"(?<!!)\[([^\]]*)\]\(\s*<?([^)\s>]+)>?[^)]*\)")


def sanitize_output_markdown(text: str, allowed_domains: set[str]) -> str:
    """Remove markdown images/links pointing outside an allow-list.

    Images are the zero-click channel (the browser fetches them automatically),
    so non-allow-listed images are dropped entirely; links keep their label only.
    """
    def host_ok(url: str) -> bool:
        parsed = urlparse(url)
        return parsed.scheme == "https" and (parsed.hostname or "") in allowed_domains

    text = _MD_IMAGE.sub(lambda m: m.group(0) if host_ok(m.group(2)) else "[image removed]", text)
    text = _MD_LINK.sub(lambda m: m.group(0) if host_ok(m.group(2)) else m.group(1), text)
    return text


# --- S-B: encoded payload detection --------------------------------------

_B64_CANDIDATE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


def decode_embedded_base64(text: str) -> list[str]:
    """Return decoded plaintext for Base64 blobs in user input so they can be
    screened by the same input classifier as plain text."""
    decoded = []
    for blob in _B64_CANDIDATE.findall(text):
        try:
            raw = base64.b64decode(blob, validate=True)
            candidate = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if candidate.isprintable() or "\n" in candidate:
            decoded.append(candidate)
    return decoded


# --- S-C: least-privilege tool gateway ------------------------------------

_READ_ONLY_SQL = re.compile(r"^\s*select\b", re.IGNORECASE)
_FORBIDDEN_SQL = re.compile(
    r"\b(drop|delete|update|insert|alter|truncate|grant|revoke|create|exec|merge)\b|;\s*\S",
    re.IGNORECASE,
)


@dataclass
class ToolDecision:
    allowed: bool
    needs_human_approval: bool = False
    reason: str = ""


@dataclass
class ToolGateway:
    """Every model-initiated tool call passes through here before execution.

    The DB tool must also run under a read-only database role: this check is a
    second layer, not a replacement for least-privilege credentials.
    """

    audit_log: list[dict] = field(default_factory=list)

    def authorize_sql(self, query: str, triggered_by_retrieved_content: bool) -> ToolDecision:
        if not _READ_ONLY_SQL.match(query) or _FORBIDDEN_SQL.search(query):
            decision = ToolDecision(False, True, "non-read-only SQL requires human approval")
        elif triggered_by_retrieved_content:
            decision = ToolDecision(False, True, "tool call originated from untrusted retrieved content")
        else:
            decision = ToolDecision(True, False, "read-only query")
        self.audit_log.append({"query": query, "decision": decision.reason, "allowed": decision.allowed})
        return decision
