from pydantic import BaseModel, Field


class AIChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)


class AIChatResponse(BaseModel):
    response: str
