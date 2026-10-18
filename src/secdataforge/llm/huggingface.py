"""Hugging Face Inference API sağlayıcısı (açık kaynak dağıtık modeller).

Hugging Face Inference API kullanır: https://huggingface.co/docs/api-inference/
Desteklenen modeller: Meta-Llama, Mistral, Qwen, DeepSeek, vb. (binlerce açık kaynak model)
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from .base import BaseLLMProvider


class HuggingFaceProvider(BaseLLMProvider):
    def __init__(
        self,
        model: str = "meta-llama/Llama-3.1-8B-Instruct",
        base_url: str = "https://api-inference.huggingface.co",
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
        if not self.api_key:
            return False
        try:
            # Model mevcut mu kontrol et
            response = self._client.get(f"{self.base_url.rstrip('/')}/models/{self.model}")
            return response.status_code == 200
        except Exception:
            return False

    def _chat_json(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        # Chat completion endpoint (LLM modelleri için)
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": self.temperature,
            "max_tokens": 4096,
            "return_full_text": False,
        }
        response = self._client.post(
            f"{self.base_url.rstrip('/')}/models/{self.model}", json=payload
        )
        response.raise_for_status()
        data = response.json()

        # Chat completion API yanıt formatı
        if isinstance(data, dict) and "choices" in data:
            content = data["choices"][0]["message"]["content"]
        elif isinstance(data, list) and data:
            content = data[0].get("generated_text", "")
        elif isinstance(data, dict):
            content = data.get("generated_text", "")
        else:
            content = str(data)

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

    def __enter__(self) -> "HuggingFaceProvider":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
