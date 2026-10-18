"""Ollama LLM sağlayıcısı (yerel, opsiyonel)."""

from __future__ import annotations

import json
from typing import Any

import httpx

from .base import BaseLLMProvider


class OllamaProvider(BaseLLMProvider):
    def __init__(
        self,
        model: str = "llama3.2",
        base_url: str = "http://localhost:11434",
        api_key: str | None = None,
        temperature: float = 0.0,
        enabled: bool = False,
        timeout: float = 120.0,
    ) -> None:
        super().__init__(model, base_url, api_key, temperature, enabled)
        self._client = httpx.Client(timeout=timeout)

    def is_available(self) -> bool:
        try:
            response = self._client.get(f"{self.base_url.rstrip('/')}/api/tags")
            if response.status_code != 200:
                return False
            # Sunucu açık olsa bile istenen model indirilmemiş olabilir
            models = response.json().get("models") or []
            if not models:
                return True
            names = {m.get("name", "") for m in models}
            if not names:
                return True
            if self.model in names:
                return True
            # "model" adı "model:latest" olarak da eşleşebilir
            return any(n.split(":")[0] == self.model for n in names)
        except Exception:
            return False

    def _chat_json(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        prompt = f"Sistem: {system_prompt}\n\nKullanıcı: {user_prompt}\n\nYanıt (sadece JSON):"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "format": "json",
            "stream": False,
            "options": {"temperature": self.temperature},
        }
        response = self._client.post(f"{self.base_url.rstrip('/')}/api/generate", json=payload)
        response.raise_for_status()
        data = response.json()
        text = data.get("response", "{}")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Bazen yanıtta JSON dışında metin olabilir; büyük harfli '{' den dene
            start = text.find("{")
            end = text.rfind("}")
            if start != -1 and end != -1 and end > start:
                return json.loads(text[start : end + 1])
            raise

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "OllamaProvider":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
