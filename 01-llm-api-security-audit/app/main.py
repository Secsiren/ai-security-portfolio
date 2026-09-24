"""Hardened reference implementation of the audited /v1/chat/completions endpoint.

The model call is stubbed so the security controls can be tested without an LLM.
Run locally:  uvicorn app.main:app --reload
"""
from __future__ import annotations

import logging
import uuid

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .guardrails import LLMQueryRequest, scan_output_for_leakage

logger = logging.getLogger("llm_api")

# Canary token embedded in the system prompt so leaks are detectable (F1).
SYSTEM_CANARY = "CANARY-7f3a91"
SYSTEM_PROMPT = (
    f"[{SYSTEM_CANARY}] You are a customer support assistant. "
    "Answer only questions about orders and returns."
)

app = FastAPI(title="LLM API - hardened reference", docs_url=None, redoc_url=None)


def call_model(system_prompt: str, user_query: str, temperature: float) -> str:
    """Stub for the LLM call. System and user content stay in separate roles (F1)."""
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_query},
    ]
    # Simulate a model that sometimes leaks its instructions, to exercise output scanning.
    if "what are your rules" in user_query.lower():
        return messages[0]["content"]
    return f"Thanks for your question about: {user_query[:80]}"


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    # Generic, structured error. No stack traces, file paths or versions (F2).
    return JSONResponse(status_code=422, content={"error": "invalid_request"})


@app.exception_handler(Exception)
async def unhandled_handler(request: Request, exc: Exception) -> JSONResponse:
    incident_id = str(uuid.uuid4())
    logger.exception("unhandled error incident_id=%s", incident_id)  # detail stays server-side
    return JSONResponse(status_code=500, content={"error": "internal_error", "incident_id": incident_id})


@app.post("/v1/chat/completions")
async def chat(req: LLMQueryRequest) -> dict:
    raw = call_model(SYSTEM_PROMPT, req.query, req.temperature)
    safe = scan_output_for_leakage(raw, [SYSTEM_CANARY, SYSTEM_PROMPT])
    return {"session_id": req.session_id, "answer": safe}
