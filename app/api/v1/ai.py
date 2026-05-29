from fastapi import APIRouter, HTTPException, Request, status

from app.rate_limiter import limiter
from app.schemas.ai import AIChatRequest, AIChatResponse
from app.services.ai_service import AIService


router = APIRouter(tags=["AI"])


@router.post("/ai/chat", response_model=AIChatResponse)
@router.post("/chat", response_model=AIChatResponse)
@limiter.limit("20/minute")
async def chat_with_assistant(request: Request, payload: AIChatRequest):
    service = AIService()
    try:
        answer = await service.chat(payload.message)
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    return AIChatResponse(response=answer)
