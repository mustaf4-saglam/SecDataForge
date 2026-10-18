"""LLM sağlayıcı arayüzü (sağlayıcı bağımsız).

LLM entegrasyonu opsiyonel ve varsayılan olarak kapalıdır. Gerçekleştiriciler
Ollama veya OpenAI uyumlu API'leri sarmalar. Tüm çıkış yapılandırılmış JSON
olarak üretilir ve Pydantic ile doğrulanır.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from ..schemas import QAPair, SecurityAdvisory


def _stable_id(*parts: str) -> str:
    """Süreçler arasında deterministik kısa kimlik üretir (tekrar eklemeyi önler)."""
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return digest[:16]


def _pick_text(data: dict[str, Any], key: str) -> str:
    """Beklenen anahtarı döndürür; yoksa tek metin değeri içeren yanıtı kabul eder.

    Bazı modeller JSON'u farklı anahtarla döndürebilir; bu durumda tek bir
    metin değeri varsa onu kullanırız. Birden fazla aday varsa güvenli tarafta
    kalınır ve boş döner (insan incelemesi gerekir).
    """
    value = data.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    strings = [v.strip() for v in data.values() if isinstance(v, str) and v and v.strip()]
    if len(strings) == 1:
        return strings[0]
    return ""


class QAGenerationOutput:
    """LLM tarafından üretilen soru-cevap çıkışı (doğrulama öncesi)."""

    def __init__(self, question: str, answer: str, grounding_fields: list[str]) -> None:
        self.question = question
        self.answer = answer
        self.grounding_fields = grounding_fields


class ClassificationOutput:
    """Kayıt sınıflandırma çıkışı."""

    def __init__(self, category: str, tags: list[str]) -> None:
        self.category = category
        self.tags = tags


class BaseLLMProvider(ABC):
    """Tüm LLM sağlayıcıları için soyut taban sınıfı."""

    def __init__(
        self,
        model: str,
        base_url: str,
        api_key: str | None = None,
        temperature: float = 0.0,
        enabled: bool = False,
    ) -> None:
        self.model = model
        self.base_url = base_url
        self.api_key = api_key
        self.temperature = temperature
        self.enabled = enabled

    @abstractmethod
    def is_available(self) -> bool:
        """Sağlayıcıya bağlanılabilir mi?"""

    @abstractmethod
    def _chat_json(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        """Yapılandırılmış JSON yanıtı iste ve döndür."""

    # ------------------------------------------------------------- görevler
    def translate_to_tr(self, text: str) -> str:
        """Güvenlik duyuru açıklamasını Türkçeye çevirir (bilgi kaybı olmadan)."""
        if not self.enabled or not text:
            return ""
        system = (
            "Sen bir siber güvenlik çevirisisin. Verilen güvenlik duyuru açıklamasını "
            "Türkçeye çevir. CVE kimlikleri, sürüm numaraları, tarihler, paket isimleri "
            "ve önem derecelerini ASLA değiştirme. "
            'Çıktı şu JSON formatında olmalı: {"translation": "<Türkçe çeviri>"}'
        )
        user = f"Metin:\n{text}"
        try:
            data = self._chat_json(system, user)
            return _pick_text(data, "translation")
        except Exception:
            return ""

    def summarize(self, text: str) -> str:
        """Kaynaktaki bilgileri koruyarak anlaşılır bir özet üretir."""
        if not self.enabled or not text:
            return ""
        system = (
            "Sen bir siber güvenlik editörüsün. Verilen açıklamayı anlaşılır bir Türkçe "
            "özetle. CVE kimlikleri, sürümler, tarihler, paket isimleri ve önem derecesini "
            "değiştirme. "
            'Çıktı şu JSON formatında olmalı: {"summary": "<Türkçe özet>"}'
        )
        user = f"Metin:\n{text}"
        try:
            data = self._chat_json(system, user)
            return _pick_text(data, "summary")
        except Exception:
            return ""

    def generate_qa(self, advisory: SecurityAdvisory, model_used: str) -> QAPair | None:
        """Kaynakla desteklenen soru-cevap çifti üretir.

        Çıktı Pydantic QAPair şemasına göre doğrulanır. Kaynakta desteklenmeyen
        iddia varsa None döner (insan incelemesine yönlendirilir).
        """
        if not self.enabled:
            return None
        system = (
            "Sen bir siber güvenlik veri mühendisisin. Verilen güvenlik duyuru kaydına "
            "dayanarak Türkçe bir soru-cevap çifti hazırla. Soru ve cevap YALNIZCA "
            "kaynakta bulunan bilgilerden çıkarıldıysa üret. CVE kimlikleri, sürüm "
            "numaraları, tarihler, paket isimleri veya önem derecesini değiştirme. "
            "Kaynakta desteklenmeyen bir iddia içeriyorsa 'supported': false dön. "
            'Çıktı şu JSON formatında olmalı: {"question":..., "answer":..., '
            '"grounding_fields":[...], "supported": true/false}'
        )
        user = (
            f"Kaynak: {advisory.source}\n"
            f"Kaynak ID: {advisory.source_id}\n"
            f"Başlık: {advisory.title or ''}\n"
            f"Açıklama: {advisory.description_original or ''}\n"
            f"CVE: {advisory.cve_ids or []}\n"
            f"Etkilenen paketler: {advisory.affected_packages or []}\n"
            f"Önem: {advisory.severity or ''}\n"
        )
        try:
            data = self._chat_json(system, user)
            if not data.get("supported", False):
                return None
            question = str(data.get("question", ""))
            qa = QAPair(
                qa_id=f"qa:{advisory.record_id}:{_stable_id(advisory.record_id, question)}",
                question=question,
                answer=str(data.get("answer", "")),
                source_record_ids=[advisory.record_id],
                grounding_fields=list(data.get("grounding_fields") or []),
                model_used=model_used,
                generated_at=datetime.now(timezone.utc),
                validation_status="pending",
                needs_human_review=True,
            )
            return qa
        except Exception:
            return None

    def suggest_remediation(self, advisory: SecurityAdvisory) -> str:
        """Önlem önerisini yalnızca kaynak bilgilerinden türetir."""
        if not self.enabled:
            return ""
        system = (
            "Sen bir siber güvenlik danışmanısın. Verilen zafiyet kaydına dayanarak "
            "Türkçe önlem (remediation) öner. Yalnızca kaynakta belirtilen bilgileri "
            "kullan; yeni ürün, sürüm veya tarih icat etme. "
            'Çıktı şu JSON formatında olmalı: {"remediation": "<Türkçe önlem>"}'
        )
        user = f"Başlık: {advisory.title or ''}\nAçıklama: {advisory.description_original or ''}"
        try:
            data = self._chat_json(system, user)
            return _pick_text(data, "remediation")
        except Exception:
            return ""

    def classify(self, advisory: SecurityAdvisory) -> ClassificationOutput | None:
        """Kayıtı tanımlı kategori ve etiketlere ayırır."""
        if not self.enabled:
            return None
        system = (
            "Sen bir siber güvenlik sınıflandırma asistanısın. Verilen zafiyet kaydını "
            'bir kategori ve etiketlere ayır. Çıktı JSON: {"category":..., "tags":[...]}'
        )
        user = f"Başlık: {advisory.title or ''}\nAçıklama: {advisory.description_original or ''}"
        try:
            data = self._chat_json(system, user)
            return ClassificationOutput(
                category=str(data.get("category", "genel")),
                tags=list(data.get("tags") or []),
            )
        except Exception:
            return None
