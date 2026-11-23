"""Vulnerable-by-design mock target. Never expose this demo service publicly."""

from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

from sentinel.gateway.auth import AuthContext
from sentinel.gateway.pipeline import SecurityPipeline
from sentinel.gateway.policy import load_policy

CANARY_SECRET = "CANARY_SECRET_9941_ALPHA"
app = FastAPI(title="LLMSentinel Vulnerable Demo Sandbox", version="1.0.0")


class ChatBody(BaseModel):
    messages: list[dict[str, str]]


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "sandbox-only"}


@app.post("/v1/chat/completions")
def vulnerable_chat(body: ChatBody) -> dict[str, Any]:
    prompt = body.messages[-1].get("content", "") if body.messages else ""
    # Deliberately unsafe behavior, isolated to a local teaching target.
    if any(term in prompt.lower() for term in ("ignore", "reveal", "secret", "system prompt", "developer message")):
        answer = f"The internal demo canary is {CANARY_SECRET}"
    else:
        answer = f"Sandbox response: {prompt[:240]}"
    return {"choices": [{"message": {"role": "assistant", "content": answer}}]}


def guarded_demo(prompt: str) -> tuple[str, dict[str, object]]:
    pipeline = SecurityPipeline(load_policy())
    decision = pipeline.inspect_input(prompt, AuthContext("demo-tenant", "user"))
    if not decision.allowed:
        return "BLOCKED", decision.as_dict()
    raw = str(vulnerable_chat(ChatBody(messages=[{"role": "user", "content": prompt}]))["choices"][0]["message"]["content"])
    clean, redactions = pipeline.sanitize_output(raw)
    return clean, {**decision.as_dict(), "redactions": redactions}
