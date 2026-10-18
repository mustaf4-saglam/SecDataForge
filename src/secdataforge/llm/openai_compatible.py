"""OpenAI uyumlu LLM sağlayıcısı (uzak, opsiyonel)."""

from __future__ import annotations

import json
from typing import Any

import httpx

from .base import BaseLLMProvider


class OpenAICompatibleProvider(BaseLLMProvider):
    def __init__(
        self,
        model: str = "gpt-3.5-turbo",
        base_url: str = "https://api.openai.com/v1",
        api_key: str | None = None,
        temperature: float = 0.0,
        enabled: bool = False,
        timeout: float = 120.0,
    ) -> None:
        super().__init__(model, base_url, api_key, temperature, enabled)
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self._client = httpx.Client(timeout=timeout, headers=headers)

    def is_available(self) -> bool:
        try:
            response = self._client.get(f"{self.base_url.rstrip('/')}/models")
            return response.status_code == 200
        except Exception:
            return False

    def _chat_json(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        payload = {
            "model": self.model,
            "temperature": self.temperature,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        response = self._client.post(f"{self.base_url.rstrip('/')}/chat/completions", json=payload)
        response.raise_for_status()
        data = response.json()
        content = data["choices"][0]["message"]["content"]
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

    def __enter__(self) -> "OpenAICompatibleProvider":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
