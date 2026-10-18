"""LLM doğrulama ve çıkış filtreleme testleri (gerçek LLM çağrısı yok)."""

from __future__ import annotations

from datetime import datetime, timezone

from secdataforge.llm.base import BaseLLMProvider
from secdataforge.schemas import QAPair, SecurityAdvisory


class _FakeProvider(BaseLLMProvider):
    def __init__(
        self, responses, model="test-model", base_url="http://localhost:11434", enabled=True
    ):
        super().__init__(model=model, base_url=base_url, enabled=enabled)
        self.responses = responses
        self.calls = []

    def is_available(self):
        return True

    def _chat_json(self, system_prompt, user_prompt):
        self.calls.append((system_prompt, user_prompt))
        return self.responses.pop(0)


def _adv():
    return SecurityAdvisory(
        record_id="rec-1",
        source="github",
        source_id="GHSA-1",
        collected_at=datetime.now(timezone.utc),
        title="XSS in foo",
        description_original="A reflected XSS in foo package.",
        cve_ids=["CVE-2024-0001"],
        affected_packages=["foo@1.0.0"],
        severity="medium",
    )


def test_generate_qa_supported_returns_qa_pair():
    provider = _FakeProvider(
        [
            {
                "question": "foo paketinde ne tür zafiyet var?",
                "answer": "Reflected XSS zafiyeti.",
                "grounding_fields": ["description_original"],
                "supported": True,
            }
        ]
    )
    qa = provider.generate_qa(_adv(), model_used="test-model")
    assert qa is not None
    assert isinstance(qa, QAPair)
    assert qa.question == "foo paketinde ne tür zafiyet var?"
    assert qa.source_record_ids == ["rec-1"]
    assert qa.validation_status == "pending"
    assert qa.needs_human_review is True


def test_generate_qa_unsupported_returns_none():
    provider = _FakeProvider(
        [{"question": "q", "answer": "a", "grounding_fields": [], "supported": False}]
    )
    qa = provider.generate_qa(_adv(), model_used="test-model")
    assert qa is None


def test_llm_disabled_returns_none():
    provider = _FakeProvider([], enabled=False)
    qa = provider.generate_qa(_adv(), model_used="m")
    assert qa is None


def test_qa_pair_model_dump():
    qa = QAPair(
        qa_id="qa-1",
        question="Soru?",
        answer="Cevap.",
        source_record_ids=["rec-1"],
        grounding_fields=["description_original"],
        model_used="m",
        generated_at=datetime.now(timezone.utc),
        validation_status="approved",
        needs_human_review=False,
    )
    data = qa.model_dump()
    assert data["qa_id"] == "qa-1"
    assert data["validation_status"] == "approved"
    assert data["needs_human_review"] is False


def test_translate_uses_expected_key():
    provider = _FakeProvider([{"translation": "Türkçe çeviri metni"}])
    assert provider.translate_to_tr("Some text") == "Türkçe çeviri metni"


def test_translate_falls_back_to_single_string_value():
    """Model farklı bir anahtar döndürse bile tek metin değeri kabul edilir."""
    provider = _FakeProvider([{"cevap": "Model kendi anahtarını üretti"}])
    assert provider.translate_to_tr("Some text") == "Model kendi anahtarını üretti"


def test_translate_ambiguous_response_returns_empty():
    """Birden fazla metin adayı varsa güvenli tarafta kalınır (boş döner)."""
    provider = _FakeProvider([{"a": "bir", "b": "iki"}])
    assert provider.translate_to_tr("Some text") == ""


def test_remediation_and_summary_keys():
    provider = _FakeProvider([{"remediation": "Sürümü güncelleyin."}, {"summary": "Kısa özet."}])
    assert provider.suggest_remediation(_adv()) == "Sürümü güncelleyin."
    assert provider.summarize("metin") == "Kısa özet."
