"""EVREN LLM API entegrasyon testleri (gerçek EVREN çağrısı YOK).

Tüm HTTP etkileşimleri httpx.MockTransport ile sahtelenir; gerçek API anahtarı
kullanılmaz ve hiçbir test dış ağa gitmez.
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from secdataforge.config import settings
from secdataforge.database import Database
from secdataforge.llm import evren as evren_mod
from secdataforge.llm.evren import (
    EvrenAPIError,
    EvrenProvider,
    accept_terms,
    require_terms,
    terms_accepted,
)
from secdataforge.llm.factory import (
    ProviderConfigError,
    create_provider,
    provider_needs_terms,
)
from secdataforge.pipeline import run_enrichment
from secdataforge.schemas import QAPair, SecurityAdvisory

DEFAULT_BASE = "https://evren-llmapi.ssyz.org.tr/v1"


def _provider(handler, model="evren-test", api_key="test-key", **kwargs):
    return EvrenProvider(
        model=model,
        api_key=api_key,
        transport=httpx.MockTransport(handler),
        **kwargs,
    )


def _err(status: int, message: str = "hata") -> httpx.Response:
    """OpenAI uyumlu hata gövdesi üretir (EVREN'in döndüğü format)."""
    return httpx.Response(
        status,
        json={
            "error": {
                "message": message,
                "type": "authentication_error",
                "param": None,
                "code": None,
            }
        },
    )


# ------------------------------------------------------------------ hata eşleme
def test_error_401_maps_to_turkish_message():
    p = _provider(lambda req: _err(401, "API anahtarı eksik"))
    with pytest.raises(EvrenAPIError) as exc:
        p.list_models()
    assert exc.value.status_code == 401
    assert "401" in exc.value.message
    assert "EVREN_API_KEY" in exc.value.message
    assert "API anahtarı eksik" in exc.value.message  # sunucu mesajı korunur


def test_error_403_404_429_5xx_mapping():
    cases = {
        403: "Kullanım şartları",
        404: "Endpoint veya model kimliği",
        429: "Kota/dakika",
        503: "HTTP 503",
    }
    for status, fragment in cases.items():
        p = _provider(lambda req, s=status: _err(s, "srv"))
        with pytest.raises(EvrenAPIError) as exc:
            p.list_models()
        assert exc.value.status_code == status
        assert fragment in exc.value.message


def test_network_error_becomes_evren_api_error():
    def _raise(req):
        raise httpx.ConnectError("bağlantı yok", request=req)

    p = _provider(_raise)
    with pytest.raises(EvrenAPIError) as exc:
        p.list_models()
    assert exc.value.status_code is None
    assert "Ağ/istek hatası" in exc.value.message


# ------------------------------------------------------------------- /models
def test_list_models_parses_openai_format():
    def handler(req):
        assert req.url.path == "/v1/models"
        return httpx.Response(200, json={"data": [{"id": "evren-a"}, {"id": "evren-b"}]})

    p = _provider(handler)
    assert p.list_models() == ["evren-a", "evren-b"]


def test_resolve_model_uses_configured_value_without_http():
    def handler(req):  # çağrı gelmemeli
        raise AssertionError("HTTP çağrılmamalı")

    p = _provider(handler, model="evren-para")
    assert p.resolve_model() == "evren-para"


def test_resolve_model_falls_back_to_first_listed_model():
    def handler(req):
        return httpx.Response(200, json={"data": [{"id": "evren-x"}]})

    p = _provider(handler, model="")
    assert p.resolve_model() == "evren-x"


def test_resolve_model_raises_when_no_model_available():
    p = _provider(lambda req: httpx.Response(200, json={"data": []}), model="")
    with pytest.raises(EvrenAPIError) as exc:
        p.resolve_model()
    assert "EVREN_MODEL" in exc.value.message


# -------------------------------------------------------------------- sohbet
def test_chat_json_success_parses_content():
    seen = {}

    def handler(req):
        if req.method == "GET":
            return httpx.Response(200, json={"data": [{"id": "evren-m"}]})
        seen["payload"] = json.loads(req.content)
        body = {"choices": [{"message": {"content": '{"cevap": "ok"}'}}]}
        return httpx.Response(200, json=body)

    p = _provider(handler, model="evren-m")
    out = p._chat_json("sys", "user")
    assert out == {"cevap": "ok"}
    assert seen["payload"]["model"] == "evren-m"
    assert seen["payload"]["messages"][0]["role"] == "system"


def test_chat_json_falls_back_when_response_format_unsupported():
    payloads = []

    def handler(req):
        if req.method == "GET":
            return httpx.Response(200, json={"data": [{"id": "evren-m"}]})
        payload = json.loads(req.content)
        payloads.append(payload)
        if "response_format" in payload:
            return httpx.Response(400, json={"error": {"message": "desteklenmiyor"}})
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"x": 1}'}}]})

    p = _provider(handler, model="evren-m")
    assert p._chat_json("s", "u") == {"x": 1}
    assert len(payloads) == 2
    assert "response_format" in payloads[0]
    assert "response_format" not in payloads[1]


def test_chat_json_wraps_network_error():
    def handler(req):
        if req.method == "GET":
            return httpx.Response(200, json={"data": [{"id": "m"}]})
        raise httpx.ReadTimeout("yavaş", request=req)

    p = _provider(handler, model="m")
    with pytest.raises(EvrenAPIError) as exc:
        p._chat_json("s", "u")
    assert exc.value.status_code is None


# ------------------------------------------------------------------- başlıklar
def test_auth_headers_sent_for_both_schemes():
    seen = {}

    def handler(req):
        seen.update(req.headers)
        return httpx.Response(200, json={"data": []})

    p = _provider(handler, api_key="SIR-ANAHTAR")
    p.list_models()
    assert seen["authorization"] == "Bearer SIR-ANAHTAR"
    assert seen["x-api-key"] == "SIR-ANAHTAR"


def test_no_auth_header_without_key():
    seen = {}

    def handler(req):
        seen.update(req.headers)
        return httpx.Response(200, json={"data": []})

    p = _provider(handler, api_key=None)
    p.list_models()
    assert "authorization" not in seen


# ------------------------------------------------------------- bağlantı testi
def test_test_connection_reports_auth_failure_honestly():
    p = _provider(lambda req: _err(401, "API anahtarı eksik"))
    result = p.test_connection(do_chat=True)
    assert result["reachable"] is True
    assert result["auth_ok"] is False
    assert result["chat_ok"] is False
    assert any("401" in e for e in result["errors"])


def test_test_connection_full_success():
    def handler(req):
        if req.method == "GET":
            return httpx.Response(200, json={"data": [{"id": "evren-m"}]})
        return httpx.Response(200, json={"choices": [{"message": {"content": "merhaba"}}]})

    p = _provider(handler, model="evren-m")
    result = p.test_connection(do_chat=True)
    assert result["reachable"] is True
    assert result["auth_ok"] is True
    assert result["models"] == ["evren-m"]
    assert result["chat_ok"] is True
    assert result["model_used"] == "evren-m"
    assert result["errors"] == []


def test_is_available_reflects_auth_state():
    assert _provider(lambda req: _err(401)).is_available() is False
    assert _provider(lambda req: httpx.Response(200, json={"data": []})).is_available() is True


# --------------------------------------------------------------- kullanım şartı
@pytest.fixture()
def terms_file(tmp_path, monkeypatch):
    path = tmp_path / "evren_terms_accepted.json"
    monkeypatch.setattr(evren_mod, "TERMS_FILE", path)
    return path


def test_require_terms_blocks_before_acceptance(terms_file):
    with pytest.raises(EvrenAPIError) as exc:
        require_terms()
    assert "evren-setup" in exc.value.message


def test_accept_terms_then_require_passes(terms_file):
    accept_terms(terms_url="https://example.org/terms", base_url=DEFAULT_BASE, api_key="gizli")
    record = terms_accepted()
    assert record is not None
    assert record["terms_url"] == "https://example.org/terms"
    assert record["confirmation"] == "explicit_user_confirmation"
    require_terms()  # hata fırlatmamalı


def test_terms_file_never_stores_api_key(terms_file):
    accept_terms(terms_url="u", base_url=DEFAULT_BASE, api_key="COK-GIZLI-ANAHTAR")
    content = terms_file.read_text(encoding="utf-8")
    assert "COK-GIZLI-ANAHTAR" not in content
    assert "api_key_fingerprint" in content
    # Parmak izi tam anahtar olmamalı
    assert len(json.loads(content)["api_key_fingerprint"]) == 12


def test_corrupt_terms_file_treated_as_not_accepted(terms_file):
    terms_file.write_text("bozuk-json", encoding="utf-8")
    assert terms_accepted() is None


# ---------------------------------------------------------------------- fabrika
def test_factory_unknown_provider_rejected():
    with pytest.raises(ProviderConfigError) as exc:
        create_provider("yok-boyle-bir-saglayici")
    assert "ollama" in str(exc.value)  # seçenekler listelenir


def test_factory_evren_requires_api_key(monkeypatch):
    monkeypatch.setattr(settings, "evren_api_key", None)
    with pytest.raises(ProviderConfigError) as exc:
        create_provider("evren")
    assert "EVREN_API_KEY" in str(exc.value)


def test_factory_evren_uses_default_base_url(monkeypatch):
    monkeypatch.setattr(settings, "evren_api_key", "k")
    p = create_provider("evren", model="evren-m")
    try:
        assert p.base_url == DEFAULT_BASE
        assert p.model == "evren-m"
    finally:
        p.close()


def test_factory_keeps_existing_providers_working():
    p = create_provider("ollama")
    try:
        assert p.base_url == settings.llm_base_url
    finally:
        p.close()


def test_terms_required_only_for_evren():
    assert provider_needs_terms("evren") is True
    assert provider_needs_terms("EVREN") is True
    assert provider_needs_terms("ollama") is False
    assert provider_needs_terms("gemini") is False


# ------------------------------------------- paylaşılan zenginleştirme (CLI/panel)
class _FakeLLM:
    model = "fake-model"

    def __init__(self):
        self._n = 0

    def translate_to_tr(self, text):
        return f"TR: {text}"

    def suggest_remediation(self, advisory):
        return "Sürümü güncelleyin."

    def generate_qa(self, advisory, model_used):
        self._n += 1
        return QAPair(
            qa_id=f"qa-fake-{self._n}",
            question="Soru?",
            answer="Cevap.",
            source_record_ids=[advisory.record_id],
            grounding_fields=["description_original"],
            model_used=model_used,
            generated_at=datetime.now(timezone.utc),
            validation_status="pending",
            needs_human_review=True,
        )


def _review_advisory(db, source_id):
    adv = SecurityAdvisory(
        record_id=f"github:{source_id}",
        source="github",
        source_id=source_id,
        collected_at="2024-01-01T00:00:00+00:00",
        published_at="2024-01-01T00:00:00+00:00",
        title=f"Title {source_id}",
        description_original=f"Desc {source_id}",
        cve_ids=["CVE-1"],
        severity="high",
        quality_status="review",
    )
    db.insert_advisory(adv)


def test_run_enrichment_shared_by_cli_and_dashboard():
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "t.db")
        _review_advisory(db, "GHSA-1")
        _review_advisory(db, "GHSA-2")

        stats = run_enrichment(db, _FakeLLM(), provider_name="fake", limit=10)
        assert stats == {"processed": 2, "enriched": 2, "qa_count": 2}

        # Türkçe metinler kalıcı
        rows = db.list_advisories(quality_status="review", limit=10)
        assert all(r.description_tr.startswith("TR: ") for r in rows)
        # QA model etiketi kaydedildi ve incelemede bekliyor
        qas = db.list_qa_pairs(validation_status="pending", limit=10)
        assert len(qas) == 2
        assert qas[0].model_used == "fake:fake-model"
        db.close()


def test_run_enrichment_respects_limit():
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "t.db")
        _review_advisory(db, "GHSA-1")
        _review_advisory(db, "GHSA-2")
        stats = run_enrichment(db, _FakeLLM(), provider_name="fake", limit=1)
        assert stats["processed"] == 1
        db.close()


def test_factory_lists_evren_among_supported_providers():
    from secdataforge.llm.factory import PROVIDER_NAMES

    assert "evren" in PROVIDER_NAMES
    assert len(PROVIDER_NAMES) >= 6
