"""LLM sağlayıcı fabrikası (CLI ve panel paylaşır).

Sağlayıcı seçimi ve API anahtarı doğrulaması tek yerde toplanır; böylece
Streamlit paneli CLI'yi taklit etmez, aynı fonksiyonları kullanır.
API anahtarları yalnızca sunucu tarafında (config/.env) okunur.
"""

from __future__ import annotations

from typing import Any

from ..config import settings
from .base import BaseLLMProvider
from .claude import ClaudeProvider
from .evren import EvrenProvider
from .gemini import GeminiProvider
from .huggingface import HuggingFaceProvider
from .ollama import OllamaProvider
from .openai_compatible import OpenAICompatibleProvider

PROVIDER_NAMES: tuple[str, ...] = (
    "ollama",
    "openai_compatible",
    "gemini",
    "claude",
    "huggingface",
    "evren",
)

# Sağlayıcı -> API anahtarının zorunlu olduğu durumda okunduğu env. değişkeni
_API_KEY_ENV: dict[str, str] = {
    "gemini": "GEMINI_API_KEY",
    "claude": "CLAUDE_API_KEY",
    "huggingface": "HUGGINGFACE_API_KEY",
    "evren": "EVREN_API_KEY",
}


class ProviderConfigError(ValueError):
    """Sağlayıcı yapılandırma hatası (ör. eksik API anahtarı)."""


def create_provider(
    provider: str,
    model: str | None = None,
    *,
    require_api_key: bool = True,
) -> BaseLLMProvider:
    """İstenen LLM sağlayıcısını üretir.

    Raises:
        ProviderConfigError: Bilinmeyen sağlayıcı veya eksik API anahtarı.
    """
    name = provider.strip().lower()

    if name == "ollama":
        return OllamaProvider(
            model=model or settings.llm_model,
            base_url=settings.llm_base_url,
            api_key=settings.llm_api_key,
            temperature=settings.llm_temperature,
            enabled=True,
            timeout=settings.llm_timeout,
        )

    if name == "openai_compatible":
        return OpenAICompatibleProvider(
            model=model or settings.llm_model,
            base_url=settings.llm_base_url,
            api_key=settings.llm_api_key,
            temperature=settings.llm_temperature,
            enabled=True,
            timeout=settings.llm_timeout,
        )

    if name == "gemini":
        api_key = settings.gemini_api_key or settings.llm_api_key
        if require_api_key and not api_key:
            raise ProviderConfigError("GEMINI_API_KEY (.env) ayarlanmamış.")
        return GeminiProvider(
            model=model or "gemini-1.5-flash",
            api_key=api_key,
            temperature=settings.llm_temperature,
            enabled=True,
            timeout=settings.llm_timeout,
        )

    if name == "claude":
        api_key = settings.claude_api_key or settings.llm_api_key
        if require_api_key and not api_key:
            raise ProviderConfigError("CLAUDE_API_KEY (.env) ayarlanmamış.")
        return ClaudeProvider(
            model=model or "claude-3-5-sonnet-20241022",
            api_key=api_key,
            temperature=settings.llm_temperature,
            enabled=True,
            timeout=settings.llm_timeout,
        )

    if name == "huggingface":
        api_key = settings.huggingface_api_key or settings.llm_api_key
        if require_api_key and not api_key:
            raise ProviderConfigError("HUGGINGFACE_API_KEY (.env) ayarlanmamış.")
        return HuggingFaceProvider(
            model=model or "meta-llama/Llama-3.1-8B-Instruct",
            api_key=api_key,
            temperature=settings.llm_temperature,
            enabled=True,
            timeout=settings.llm_timeout,
        )

    if name == "evren":
        api_key = settings.evren_api_key
        if require_api_key and not api_key:
            raise ProviderConfigError("EVREN_API_KEY (.env) ayarlanmamış.")
        return EvrenProvider(
            model=model,
            api_key=api_key,
            temperature=settings.llm_temperature,
            enabled=True,
            timeout=settings.llm_timeout,
        )

    raise ProviderConfigError(
        f"Bilinmeyen sağlayıcı: {provider} (seçenekler: {', '.join(PROVIDER_NAMES)})"
    )


def provider_needs_terms(provider: str) -> bool:
    """Sağlayıcı için kullanım şartı onayı gerekli mi? (şu an yalnızca EVREN)."""
    return provider.strip().lower() == "evren"


def describe_provider(provider: str, inst: BaseLLMProvider) -> dict[str, Any]:
    """Panelde gösterilecek güvenli (anahtar içermeyen) tanım."""
    return {
        "provider": provider,
        "model": inst.model,
        "base_url": inst.base_url,
        "api_key_configured": bool(inst.api_key),
    }
