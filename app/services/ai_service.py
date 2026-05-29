from __future__ import annotations

import logging

import httpx

from app.config import settings


logger = logging.getLogger(__name__)


SYSTEM_PROMPT = (
    "You are the ThreatChain cybersecurity assistant. "
    "Give concise, beginner-friendly, practical explanations about IOCs, malware behavior, "
    "threat actors, blockchain verification, TLP levels, false-positive lifecycle, and trust score concepts. "
    "Do not invent unavailable ThreatChain data. "
    "If data is unavailable, clearly say so. "
    "Keep responses professional and short unless more detail is explicitly requested."
)


class AIService:
    def __init__(self) -> None:
        self.base_url = settings.OLLAMA_BASE_URL.rstrip("/")
        self.model = settings.OLLAMA_MODEL
        self.timeout_seconds = float(settings.OLLAMA_TIMEOUT_SECONDS)

    async def chat(self, message: str) -> str:
        payload = {
            "model": self.model,
            "stream": False,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": message},
            ],
            "options": {
                "temperature": 0.2,
                "top_p": 0.9,
                "num_predict": 220,
            },
        }

        url = f"{self.base_url}/api/chat"
        timeout = httpx.Timeout(self.timeout_seconds)

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
        except httpx.TimeoutException as exc:
            raise RuntimeError("AI assistant timed out while generating a response.") from exc
        except httpx.HTTPStatusError as exc:
            logger.exception("Ollama returned non-success status", extra={"status_code": exc.response.status_code})
            raise RuntimeError("AI assistant is currently unavailable.") from exc
        except httpx.HTTPError as exc:
            logger.exception("Failed to reach Ollama service")
            raise RuntimeError("AI assistant is currently unavailable.") from exc

        content = ""
        message_payload = data.get("message")
        if isinstance(message_payload, dict):
            raw_content = message_payload.get("content")
            if isinstance(raw_content, str):
                content = raw_content.strip()
        if not content and isinstance(data.get("response"), str):
            content = data["response"].strip()
        if not content:
            raise RuntimeError("AI assistant returned an empty response.")
        return content
