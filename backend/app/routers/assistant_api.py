"""AI analyst endpoints (Claude API). Answers stream as server-sent events."""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from .. import assistant
from ..auth import can, require

router = APIRouter(prefix="/api/assistant")

SUGGESTIONS = {
    "executive": [
        "Give me a one-paragraph briefing on our cyber risk this week.",
        "What are the top three decisions I need to make, and why?",
        "Which critical vendors should I be worried about?",
        "Are we ready for the upcoming SOC 2 and ISO audits?",
    ],
    "analyst": [
        "What should I patch first today, and why?",
        "Which actively exploited vulnerabilities are on internet-facing hosts with no ticket?",
        "Summarize the phishing activity from the last 30 days.",
        "How is the enterprise risk score calculated, and what is driving it?",
    ],
}


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    conversation_id: str | None = Field(None, max_length=64)


@router.get("/status")
def status(user=Depends(require("use_assistant"))):
    return {"configured": assistant.configured(), "model": assistant.MODEL,
            "tools": [t.name for t in assistant.tools_for(user)],
            "suggestions": SUGGESTIONS["executive" if not can(user, "view_details") else "analyst"]}


@router.post("/chat")
def chat(body: ChatRequest, user=Depends(require("use_assistant"))):
    if not assistant.configured():
        raise HTTPException(503, "The AI analyst is not configured. Set ANTHROPIC_API_KEY on the server.")
    if assistant.rate_limited(user["username"]):
        raise HTTPException(429, "Too many questions in a short time. Please wait a few minutes.")
    return StreamingResponse(assistant.chat(user, body.message.strip(), body.conversation_id),
                             media_type="text/event-stream", headers={"X-Accel-Buffering": "no"})
