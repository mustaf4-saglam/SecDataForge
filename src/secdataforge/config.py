"""Uygulama yapılandırması (.env ortam dosyasından okunur).

Gizli bilgiler (API anahtarı vb.) kod içine yazılmaz. ``.env.example``
dosyası kopyalanarak ``.env`` olarak düzenlenmelidir.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel, Field

# Proje kök dizini: src/secdataforge/config.py -> iki üstü = repo kökü
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
EXPORTS_DIR = DATA_DIR / "exports"
DB_PATH = DATA_DIR / "secdataforge.db"

# .env dosyasını yükle (varsa); mevcut ortam değişkenleri ezilmez.
load_dotenv(BASE_DIR / ".env", override=False)


class Settings(BaseModel):
    """Uygulama ayarları. Tüm alanlar ortam değişkeninden okunabilir."""

    app_name: str = "secdataforge"
    db_path: Path = DB_PATH
    data_dir: Path = DATA_DIR
    raw_dir: Path = RAW_DIR
    processed_dir: Path = PROCESSED_DIR
    exports_dir: Path = EXPORTS_DIR
    default_record_limit: int = Field(
        default=100, description="Kaynak başına varsayılan maksimum kayıt sayısı."
    )
    request_timeout: float = Field(default=30.0, description="HTTP istek zaman aşımı (saniye).")
    max_retries: int = Field(default=3, description="Maksimum yeniden deneme sayısı.")
    backoff_factor: float = Field(default=2.0, description="Artan bekleme katsayısı.")

    # GitHub Global Security Advisories
    github_token: str | None = Field(default=None)
    github_base_url: str = "https://api.github.com"

    # OSV Vulnerability API
    osv_base_url: str = "https://api.osv.dev/v1"

    # LLM (opsiyonel, varsayılan olarak kapalı)
    llm_enabled: bool = False
    llm_provider: str = Field(
        default="ollama",
        description="ollama | openai_compatible | gemini | claude | huggingface | evren | none",
    )
    llm_base_url: str = "http://localhost:11434"
    llm_model: str = "llama3.2"
    llm_api_key: str | None = None
    llm_temperature: float = 0.0
    llm_timeout: float = Field(
        default=120.0,
        description="LLM istek zaman aşımı (saniye); yavaş yerel modeller artırılabilir.",
    )

    # Sağlayıcı bazlı API anahtarı (LLM_API_KEY kullanılmıyorsa öncelikli)
    gemini_api_key: str | None = None
    claude_api_key: str | None = None
    huggingface_api_key: str | None = None

    # EVREN LLM API (Türkiye, SAYZEK ekosistemi; OpenAI uyumlu)
    # API anahtarı asla koda/versiyon kontrolüne yazılmaz; sadece .env'de okunur.
    evren_api_key: str | None = None
    evren_base_url: str = "https://evren-llmapi.ssyz.org.tr/v1"
    evren_model: str | None = Field(
        default=None,
        description="EVREN model kimliği; boşsa /models listesinden ilk model seçilir.",
    )
    evren_terms_url: str = "https://evren-llmapi.ssyz.org.tr"

    @classmethod
    def from_env(cls) -> "Settings":
        def _env(key: str, default=None):
            return os.getenv(key, default)

        return cls(
            db_path=Path(_env("DB_PATH", str(DB_PATH))),
            data_dir=Path(_env("DATA_DIR", str(DATA_DIR))),
            raw_dir=Path(_env("RAW_DIR", str(RAW_DIR))),
            processed_dir=Path(_env("PROCESSED_DIR", str(PROCESSED_DIR))),
            exports_dir=Path(_env("EXPORTS_DIR", str(EXPORTS_DIR))),
            default_record_limit=int(_env("DEFAULT_RECORD_LIMIT", "100")),
            request_timeout=float(_env("REQUEST_TIMEOUT", "30.0")),
            max_retries=int(_env("MAX_RETRIES", "3")),
            backoff_factor=float(_env("BACKOFF_FACTOR", "2.0")),
            github_token=_env("GITHUB_TOKEN"),
            github_base_url=_env("GITHUB_BASE_URL", "https://api.github.com"),
            osv_base_url=_env("OSV_BASE_URL", "https://api.osv.dev/v1"),
            llm_enabled=_env("LLM_ENABLED", "false").lower() in ("1", "true", "yes", "on"),
            llm_provider=_env("LLM_PROVIDER", "ollama"),
            llm_base_url=_env("LLM_BASE_URL", "http://localhost:11434"),
            llm_model=_env("LLM_MODEL", "llama3.2"),
            llm_api_key=_env("LLM_API_KEY"),
            llm_temperature=float(_env("LLM_TEMPERATURE", "0.0")),
            llm_timeout=float(_env("LLM_TIMEOUT", "120.0")),
            gemini_api_key=_env("GEMINI_API_KEY"),
            claude_api_key=_env("CLAUDE_API_KEY") or _env("ANTHROPIC_API_KEY"),
            huggingface_api_key=_env("HUGGINGFACE_API_KEY") or _env("HF_API_KEY"),
            evren_api_key=_env("EVREN_API_KEY"),
            evren_base_url=_env("EVREN_BASE_URL", "https://evren-llmapi.ssyz.org.tr/v1"),
            evren_model=_env("EVREN_MODEL"),
            evren_terms_url=_env("EVREN_TERMS_URL", "https://evren-llmapi.ssyz.org.tr"),
        )


settings = Settings.from_env()
