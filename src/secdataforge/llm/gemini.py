"""Google Gemini LLM sağlayıcısı (uzak, opsiyonel).

Google AI Studio API kullanır: https://ai.google.dev/
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from .base import BaseLLMProvider


class GeminiProvider(BaseLLMProvider):
    def __init__(
        self,
        model: str = "gemini-1.5-flash",
        base_url: str = "https://generativelanguage.googleapis.com/v1beta",
        api_key: str | None = None,
        temperature: float = 0.0,
        enabled: bool = False,
        timeout: float = 120.0,
    ) -> None:
        super().__init__(model, base_url, api_key, temperature, enabled)
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            headers["x-goog-api-key"] = api_key
        self._client = httpx.Client(timeout=timeout, headers=headers)

    def is_available(self) -> bool:
        if not self.api_key:
            return False
        try:
            response = self._client.get(f"{self.base_url.rstrip('/')}/models")
            return response.status_code == 200
        except Exception:
            return False

    def _chat_json(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        # Gemini 1.5+ sistemi ve kullanıcıyı ayrı message olarak alır
        payload = {
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": {
                "temperature": self.temperature,
                "responseMimeType": "application/json",
            },
        }
        url = f"{self.base_url.rstrip('/')}/models/{self.model}:generateContent"
        response = self._client.post(url, json=payload)
        response.raise_for_status()
        data = response.json()
        content = data["candidates"][0]["content"]["parts"][0]["text"]
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            start = content.find("{")
            end = content.rfind("}")
            if start != -1 and end != -1 and end > start:
                return json.loads(content[start : end + 1])
            raise

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "GeminiProvider":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
