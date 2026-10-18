"""EVREN LLM API sağlayıcısı (Türkiye, SAYZEK ekosistemi).

EVREN, OpenAI uyumlu bir REST API sunar:
- Base URL: https://evren-llmapi.ssyz.org.tr/v1
- ``POST /chat/completions`` ve ``GET /models``
- Kimlik doğrulama: ``Authorization: Bearer <API_KEY>`` (veya ``X-API-Key``)

Bu sağlayıcı ``OpenAICompatibleProvider``'ı genişletir; EVREN'e özel olarak:
- HTTP hata kodlarının (401/403/404/429/5xx) Türkçe ve açıklayıcı eşlemesi
- ``/models`` üzerinden gerçek model listesi ve model çözümleme
- Kullanım şartı onayının zorunlu kılınması (otomatik onay YOK)
- Bağlantı testi (erişim / kimlik / model / kısa sohbet)

Not: ``response_format`` desteklemeyen EVREN dağıtımları için otomatik geri
düşme (fallback) vardır.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import httpx

from ..config import settings
from .openai_compatible import OpenAICompatibleProvider

# Kullanım şartı onayının tutulduğu yerel dosya (Git'e girmez; data/ gitignore'da).
# API anahtarı BURADA ASLA SAKLANMAZ; yalnızca parmak izi (sha256[:12]) tutulur.
TERMS_FILE: Path = settings.data_dir / "evren_terms_accepted.json"


class EvrenAPIError(RuntimeError):
    """EVREN API hatası (varsa HTTP durum kodu ile)."""

    def __init__(self, status_code: int | None, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message


# HTTP durum kodu -> Türkçe, açıklayıcı mesaj
ERROR_MESSAGES: dict[int, str] = {
    401: "Kimlik doğrulama hatası (401): EVREN_API_KEY geçersiz veya eksik.",
    403: "Erişim reddedildi (403): Kullanım şartları onaylanmamış veya erişim izni yok.",
    404: "Bulunamadı (404): Endpoint veya model kimliği yanlış.",
    429: "İstek sınırı aşıldı (429): Kota/dakika limiti aşıldı; bekleyip tekrar deneyin.",
}


# ------------------------------------------------------------ kullanım şartı
def terms_accepted() -> dict[str, Any] | None:
    """Kullanım şartları onay kaydı varsa döndürür, yoksa None."""
    if not TERMS_FILE.exists():
        return None
    try:
        return json.loads(TERMS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def accept_terms(*, terms_url: str, base_url: str, api_key: str | None = None) -> Path:
    """Açık onay sonrası şart kabulünü kaydeder.

    API anahtarı yalnızca parmak izi (sha256[:12]) olarak saklanır; tam anahtar
    hiçbir yere yazılmaz.
    """
    import datetime as _dt

    TERMS_FILE.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "accepted_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "terms_url": terms_url,
        "base_url": base_url,
        "confirmation": "explicit_user_confirmation",
    }
    if api_key:
        payload["api_key_fingerprint"] = hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:12]
    TERMS_FILE.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return TERMS_FILE


def require_terms() -> None:
    """Şartlar onaylanmamışsa açıklayıcı hata fırlatır (otomatik onay yok)."""
    if terms_accepted() is None:
        raise EvrenAPIError(
            None,
            "EVREN kullanım şartları henüz onaylanmadı. Önce şu komutu çalıştırıp "
            "şartları okuyun ve açık onay verin: secdataforge evren-setup",
        )


# ------------------------------------------------------------------ sağlayıcı
_UNSET = object()  # api_key için "ayarlanmamış" ayrımı (None anahtar yok sayar)


class EvrenProvider(OpenAICompatibleProvider):
    """EVREN LLM API istemcisi (OpenAI uyumlu)."""

    DEFAULT_BASE_URL = "https://evren-llmapi.ssyz.org.tr/v1"

    def __init__(
        self,
        model: str | None = None,
        base_url: str | None = None,
        api_key: object = _UNSET,
        temperature: float | None = None,
        enabled: bool = False,
        timeout: float | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        base = (base_url or settings.evren_base_url or self.DEFAULT_BASE_URL).rstrip("/")
        key = settings.evren_api_key if api_key is _UNSET else api_key  # type: ignore[assignment]
        resolved_model = model if model is not None else (settings.evren_model or "")
        temp = temperature if temperature is not None else settings.llm_temperature
        to = timeout if timeout is not None else settings.llm_timeout
        super().__init__(
            model=resolved_model,
            base_url=base,
            api_key=key,
            temperature=temp,
            enabled=enabled,
            timeout=to,
        )
        self._transport = transport
        # Üst sınıf kendi istemcisini kurar; EVREN hem Bearer hem X-API-Key
        # kabul ettiğinden istemciyi bu başlıklarla yeniden kuruyoruz.
        self._rebuild_client(to)

    def _rebuild_client(self, timeout: float) -> None:
        self.close()
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
            headers["X-API-Key"] = self.api_key
        self._client = httpx.Client(timeout=timeout, headers=headers, transport=self._transport)

    def _raise_mapped(self, response: httpx.Response) -> None:
        """HTTP hatasını Türkçe, açıklayıcı EvrenAPIError'a çevirir."""
        if response.status_code < 400:
            return
        message = ERROR_MESSAGES.get(
            response.status_code, f"EVREN API hatası (HTTP {response.status_code})."
        )
        try:
            detail = (response.json().get("error") or {}).get("message")
        except Exception:
            detail = None
        if detail:
            message = f"{message} Sunucu mesajı: {detail}"
        raise EvrenAPIError(response.status_code, message)

    def list_models(self) -> list[str]:
        """``GET /models`` üzerinden erişilebilir model kimliklerini döndürür."""
        try:
            response = self._client.get(f"{self.base_url}/models")
        except httpx.HTTPError as exc:
            raise EvrenAPIError(None, f"Ağ/istek hatası: {exc}") from exc
        self._raise_mapped(response)
        data = response.json().get("data") or []
        return [m["id"] for m in data if isinstance(m, dict) and m.get("id")]

    def resolve_model(self) -> str:
        """EVREN_MODEL verilmişse onu; yoksa /models listesinden ilk modeli seçer.

        Model adları ASLA tahmin edilmez; her zaman API'nin döndüğü listeden gelir.
        """
        if self.model:
            return self.model
        models = self.list_models()
        if not models:
            raise EvrenAPIError(
                None,
                "EVREN_MODEL ayarlanmamış ve /models boş döndü; geçerli bir model "
                "kimliği belirtin (secdataforge evren-test ile listeleyin).",
            )
        return models[0]

    def is_available(self) -> bool:
        """API'ye erişilebilir ve kimlik geçerli mi? (hata ayrıntısı isteğe bağlı testte)"""
        try:
            response = self._client.get(f"{self.base_url}/models")
            return response.status_code == 200
        except Exception:
            return False

    def test_connection(self, do_chat: bool = True) -> dict[str, Any]:
        """Bağlantı testi: erişim → kimlik → model listesi → kısa sohbet.

        Her adım ayrı ayrı raporlanır; başarısız adımlar gizlenmez.
        """
        result: dict[str, Any] = {
            "base_url": self.base_url,
            "reachable": False,
            "auth_ok": False,
            "models": [],
            "model_used": None,
            "chat_ok": False,
            "errors": [],
        }
        try:
            response = self._client.get(f"{self.base_url}/models")
            result["reachable"] = True
            if response.status_code == 200:
                result["auth_ok"] = True
                result["models"] = self.list_models()
            else:
                self._raise_mapped(response)
        except EvrenAPIError as exc:
            result["errors"].append(exc.message)
            return result
        except httpx.HTTPError as exc:
            result["errors"].append(f"Ağ/istek hatası: {exc}")
            return result

        if do_chat:
            try:
                model = self.resolve_model()
                result["model_used"] = model
                payload = {
                    "model": model,
                    "temperature": 0.0,
                    # Düşünme (reasoning) modelleri küçük bütçeyi harcayıp boş
                    # content döndürebilir; bu yüzden cömert bütçe verilir.
                    "max_tokens": 256,
                    "messages": [{"role": "user", "content": "Merhaba, tek kelimeyle yanıtla."}],
                }
                response = self._client.post(f"{self.base_url}/chat/completions", json=payload)
                self._raise_mapped(response)
                content = response.json()["choices"][0]["message"]["content"]
                result["chat_ok"] = bool(content and content.strip())
                if not result["chat_ok"]:
                    result["errors"].append(
                        "Model boş yanıt döndürdü: bu model metin üretimini (sohbet) "
                        "desteklemiyor olabilir (karar/OCR/embedding modelleri). "
                        "EVREN_MODEL değiştirin; sohbet döndüren modelleri "
                        "`secdataforge evren-test` ile deneyin."
                    )
            except EvrenAPIError as exc:
                result["errors"].append(exc.message)
            except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
                result["errors"].append(f"Sohbet testi hatası: {exc}")
        return result

    def _chat_json(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        model = self.resolve_model()
        payload: dict[str, Any] = {
            "model": model,
            "temperature": self.temperature,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        # Bazı EVREN dağıtımları response_format'ı desteklemeyebilir: önce dene,
        # 400 alırsan desteklenmeyen alanı çıkarıp tekrar dene.
        url = f"{self.base_url}/chat/completions"
        try:
            response = self._client.post(
                url, json={**payload, "response_format": {"type": "json_object"}}
            )
            if response.status_code == 400:
                response = self._client.post(url, json=payload)
            self._raise_mapped(response)
        except httpx.HTTPError as exc:
            raise EvrenAPIError(None, f"Ağ/istek hatası: {exc}") from exc

        content = response.json()["choices"][0]["message"]["content"]
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            start = content.find("{")
            end = content.rfind("}")
            if start != -1 and end != -1 and end > start:
                return json.loads(content[start : end + 1])
            raise
