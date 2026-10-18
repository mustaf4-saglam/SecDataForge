"""Veri kaynağı bağlayıcılarının ortak taban sınıfı.

Her bağlayıcı şu özellikleri destekler:
- Yapılandırılabilir kayıt limiti ve filtreler
- Sayfalama ve devam ettirme
- Zaman aşımı, sınırlı yeniden deneme ve artan bekleme süresi
- HTTP 429 ve API hatalarının yönetimi
- Tekrar çalıştırılabilir, idempotent işlemler
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

import httpx

from ..config import settings
from ..schemas import LicenseStatus, RawRecord


class ConnectorConfig:
    """Bağlayıcı yapılandırması."""

    def __init__(
        self,
        name: str,
        base_url: str,
        record_limit: int | None = None,
        timeout: float | None = None,
        max_retries: int | None = None,
        backoff_factor: float | None = None,
        license: str | None = None,
        license_status: LicenseStatus = LicenseStatus.unknown,
        filters: dict[str, Any] | None = None,
        enabled: bool = True,
    ) -> None:
        self.name = name
        self.base_url = base_url
        self.record_limit = (
            record_limit if record_limit is not None else settings.default_record_limit
        )
        self.timeout = timeout if timeout is not None else settings.request_timeout
        self.max_retries = max_retries if max_retries is not None else settings.max_retries
        self.backoff_factor = (
            backoff_factor if backoff_factor is not None else settings.backoff_factor
        )
        self.license = license
        self.license_status = license_status
        self.filters = filters or {}
        self.enabled = enabled


class FetchResult:
    """Bir bağlayıcı tarafından döndürülen ham kayıtlar ve hata bilgisi."""

    def __init__(
        self,
        source: str,
        records: list[dict[str, Any]],
        errors: list[str] | None = None,
        next_cursor: Any = None,
    ) -> None:
        self.source = source
        self.records = records
        self.errors = errors or []
        self.next_cursor = next_cursor


class BaseConnector(ABC):
    """Tüm kaynak bağlayıcıları için soyut taban sınıfı."""

    def __init__(self, config: ConnectorConfig) -> None:
        self.config = config
        self._client = httpx.Client(
            timeout=config.timeout,
            headers={"Accept": "application/json", "User-Agent": "secdataforge/0.1"},
        )
        if config.name == "github" and settings.github_token:
            self._client.headers["Authorization"] = f"Bearer {settings.github_token}"

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "BaseConnector":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ------------------------------------------------------------------ HTTP
    def _request_with_retry(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
    ) -> httpx.Response:
        """Zaman aşımı, 429 sınırlama ve artan beklemeyle HTTP isteği yapar."""
        last_error: str | None = None
        delay = 1.0
        for attempt in range(1, self.config.max_retries + 1):
            try:
                response = self._client.request(method, url, params=params, json=json)
                if response.status_code == 429:
                    retry_after = response.headers.get("Retry-After")
                    wait = float(retry_after) if retry_after else delay
                    last_error = f"HTTP 429 rate limited (attempt {attempt}), waiting {wait}s"
                    time.sleep(min(wait, 60.0))
                    delay *= self.config.backoff_factor
                    continue
                if response.status_code >= 500:
                    last_error = f"HTTP {response.status_code} server error (attempt {attempt})"
                    time.sleep(delay)
                    delay *= self.config.backoff_factor
                    continue
                return response
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_error = f"{type(exc).__name__}: {exc} (attempt {attempt})"
                time.sleep(delay)
                delay *= self.config.backoff_factor
        raise RuntimeError(last_error or "HTTP isteği başarısız oldu")

    @staticmethod
    def _make_raw_id(source: str, source_id: str) -> str:
        return f"{source}:{source_id}:{uuid.uuid4().hex[:8]}"

    @staticmethod
    def _hash_payload(payload: dict[str, Any]) -> str:
        canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    # ----------------------------------------------------------------- abstract
    @abstractmethod
    def fetch(self, limit: int | None = None, cursor: Any = None) -> FetchResult:
        """Kaynaktan ham kayıtları çeker (sayfalı)."""

    @abstractmethod
    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Ham yanıtı ortak şema alanlarına dönüştürür (dict döner)."""

    @abstractmethod
    def enrich(self, source_id: str) -> dict[str, Any] | None:
        """Tek bir kaynağın kaydını zenginleştirir (opsiyonel)."""

    def to_raw_record(self, source: str, source_id: str, response: httpx.Response) -> RawRecord:
        """HTTP yanıtından RawRecord oluşturur."""
        try:
            payload = response.json()
        except Exception:
            payload = {"text": response.text}
        raw_hash = self._hash_payload(payload) if isinstance(payload, dict) else ""
        return RawRecord(
            raw_id=self._make_raw_id(source, source_id),
            source=source,
            source_id=source_id,
            fetched_at=self._now(),
            http_status=response.status_code,
            raw_payload=payload,
            etag=response.headers.get("ETag"),
            raw_hash=raw_hash or None,
        )
