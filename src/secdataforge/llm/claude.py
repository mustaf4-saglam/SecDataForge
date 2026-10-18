"""Anthropic Claude LLM sağlayıcısı (uzak, opsiyonel).

Anthropic API kullanır: https://docs.anthropic.com/
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from .base import BaseLLMProvider


class ClaudeProvider(BaseLLMProvider):
    def __init__(
        self,
        model: str = "claude-3-5-sonnet-20241022",
        base_url: str = "https://api.anthropic.com/v1",
        api_key: str | None = None,
        temperature: float = 0.0,
        enabled: bool = False,
        timeout: float = 120.0,
    ) -> None:
        super().__init__(model, base_url, api_key, temperature, enabled)
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        }
        if api_key:
            headers["x-api-key"] = api_key
        self._client = httpx.Client(timeout=timeout, headers=headers)

    def is_available(self) -> bool:
        if not self.api_key:
            return False
        try:
            # Claude models endpoint'i yok; basit bir istek deneyelim
            response = self._client.get(f"{self.base_url.rstrip('/')}/models")
            return response.status_code == 200
        except Exception:
            return False

    def _chat_json(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        payload = {
            "model": self.model,
            "max_tokens": 4096,
            "temperature": self.temperature,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
            "response_format": {"type": "json_object"},
        }
        response = self._client.post(f"{self.base_url.rstrip('/')}/messages", json=payload)
        response.raise_for_status()
        data = response.json()
        content = data["content"][0]["text"]
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

    def __enter__(self) -> "ClaudeProvider":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
