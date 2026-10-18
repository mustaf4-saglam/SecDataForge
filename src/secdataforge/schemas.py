"""Ortak veri şeması (Pydantic).

Güvenlik duyurusu kayıtları, ham veri arşivi, LLM üretilen soru-cevap örnekleri
ve işlem durumu modelleri burada tanımlanır. Alanların bulunamaması normal
olabileceğinden uygun alanlar nullable tutulmuştur.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, HttpUrl


class QualityStatus(str, Enum):
    pending = "pending"
    valid = "valid"
    review = "review"
    rejected = "rejected"


class LicenseStatus(str, Enum):
    allowed = "allowed"
    restricted = "restricted"
    unknown = "unknown"


class SourceRunStatus(str, Enum):
    running = "running"
    completed = "completed"
    failed = "failed"
    partial = "partial"


class RawRecord(BaseModel):
    """Kaynak tarafından döngüye alınan ham yanıt (yeniden incelenebilir)."""

    raw_id: str = Field(description="Benzersiz ham kayıt kimliği.")
    source: str = Field(description="Kaynak adı (ör. github, osv).")
    source_id: str = Field(description="Kaynaktaki kayıt kimliği (ör. GHSA-xxxx, CVE-xxxx).")
    fetched_at: datetime = Field(description="Kayıtın çekildiği tarih.")
    http_status: int = Field(description="HTTP yanıt durumu kodu.")
    raw_payload: dict[str, Any] = Field(description="Kaynak tarafından döndürülen ham JSON.")
    etag: Optional[str] = Field(default=None, description="HTTP ETag / sürüm imzası.")
    raw_hash: Optional[str] = Field(
        default=None, description="Ham payload'ın SHA-256 özeti (aşırı-basit değişlik tespiti)."
    )


class SecurityAdvisory(BaseModel):
    """Ortak güvenlik duyurusu şeması."""

    record_id: str = Field(description="Uygulama içi benzersiz kayıt kimliği.")
    source: str = Field(description="Kaynak adı.")
    source_id: str = Field(description="Kaynaktaki orijinal kimlik.")
    source_url: Optional[HttpUrl] = Field(default=None, description="Kaynak URL'i.")
    license: Optional[str] = Field(default=None, description="İçerik lisansı.")
    license_status: Optional[LicenseStatus] = Field(
        default=None, description="Lisans yeniden kullanım durumu."
    )
    collected_at: datetime = Field(description="Veri toplaması tarihi.")
    published_at: Optional[datetime] = Field(default=None, description="Yayın tarihi.")
    modified_at: Optional[datetime] = Field(default=None, description="Son değişiklik tarihi.")
    title: Optional[str] = Field(default=None, description="Başlık.")
    description_original: Optional[str] = Field(default=None, description="Orijinal açıklama.")
    description_tr: Optional[str] = Field(default=None, description="Türkçe açıklama.")
    cve_ids: Optional[list[str]] = Field(default=None, description="İlişkili CVE kimlikleri.")
    cwe_ids: Optional[list[str]] = Field(default=None, description="İlişkili CWE kimlikleri.")
    affected_packages: Optional[list[str]] = Field(
        default=None, description="Etkilenen paketler (paket@sürüm biçiminde)."
    )
    severity: Optional[str] = Field(default=None, description="Önem derecesi.")
    references: Optional[list[str]] = Field(default=None, description="Referans bağlantılar.")
    remediation_tr: Optional[str] = Field(default=None, description="Türkçe önlem önerisi.")
    raw_hash: Optional[str] = Field(default=None, description="Ham veri özeti.")
    quality_status: QualityStatus = Field(
        default=QualityStatus.pending, description="Kalite durumudur."
    )
    quality_issues: Optional[list[str]] = Field(
        default=None, description="Tespit edilen kalite sorunları."
    )

    def dedupe_key(self) -> str:
        """Tekrar tespiti için anahtar: CVE kimlikleri yoksa source_id kullanılır."""
        cves = sorted(self.cve_ids or [])
        if cves:
            return "cve:" + "|".join(cves)
        return f"source:{self.source}:{self.source_id}"


class QAPair(BaseModel):
    """LLM tarafından üretilen soru-cevap örneği."""

    qa_id: str = Field(description="Benzersiz QA kimliği.")
    question: str = Field(description="Soru.")
    answer: str = Field(description="Cevap.")
    source_record_ids: list[str] = Field(
        default_factory=list, description="İlgili kaynak kayıt kimlikleri."
    )
    grounding_fields: list[str] = Field(
        default_factory=list, description="Dayanak olarak kullanılan kaynak alanları."
    )
    model_used: str = Field(description="Kullanılan LLM modeli.")
    generated_at: datetime = Field(description="Üretim tarihi.")
    validation_status: str = Field(default="pending", description="pending | approved | rejected")
    needs_human_review: bool = Field(
        default=True, description="İnsan incelemesi gerekip gerekmediği."
    )


class SourceRun(BaseModel):
    """Kaynak bazlı işlem durumu (izlenebilirlik)."""

    run_id: str = Field(description="Benzersiz işlem kimliği.")
    source: str = Field(description="Kaynak adı.")
    status: SourceRunStatus = Field(default=SourceRunStatus.running)
    started_at: datetime = Field(description="Başlangıç tarihi.")
    completed_at: Optional[datetime] = Field(default=None)
    records_fetched: int = Field(default=0)
    records_inserted: int = Field(default=0)
    duplicates: int = Field(default=0)
    errors: int = Field(default=0)
    error_message: Optional[str] = Field(default=None)
    next_cursor: Optional[str] = Field(
        default=None, description="Devam ettirme için son sayfa imleci (--resume)."
    )


class ProcessingError(BaseModel):
    """İşlem sırasında oluşan hatalar."""

    error_id: str = Field(description="Benzersiz hata kimliği.")
    source: str = Field(description="Hata oluştuğu kaynak.")
    stage: str = Field(description="Hata oluştuğu işlem hattı aşaması.")
    record_id: Optional[str] = Field(default=None, description="İlişkili kayıt kimliği.")
    message: str = Field(description="Hata mesajı.")
    occurred_at: datetime = Field(description="Oluşma tarihi.")


class QualityReport(BaseModel):
    """Veri kalitesi raporu."""

    total_fetched: int = Field(default=0)
    total_inserted: int = Field(default=0)
    total_duplicates: int = Field(default=0)
    total_errors: int = Field(default=0)
    missing_field_ratio: float = Field(default=0.0)
    unknown_license_count: int = Field(default=0)
    translated_count: int = Field(default=0)
    pending_ai_review: int = Field(default=0)
    approved_qa_count: int = Field(default=0)
    orphan_qa_count: int = Field(default=0)
    by_source: dict[str, dict[str, int]] = Field(default_factory=dict)
