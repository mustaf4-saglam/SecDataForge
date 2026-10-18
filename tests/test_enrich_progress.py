"""Zenginleştirme ilerleme takibi (on_progress) testleri — gerçek LLM çağrısı YOK."""

from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path

from secdataforge.database import Database
from secdataforge.pipeline import format_progress_line, run_enrichment
from secdataforge.schemas import QAPair, SecurityAdvisory


def _insert_review(db, source_id):
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


class _GoodLLM:
    model = "good-model"

    def translate_to_tr(self, text):
        return f"TR: {text}"

    def suggest_remediation(self, advisory):
        return "Sürümü güncelleyin."

    def generate_qa(self, advisory, model_used):
        return QAPair(
            qa_id=f"qa-{advisory.source_id}",
            question="Soru?",
            answer="Cevap.",
            source_record_ids=[advisory.record_id],
            grounding_fields=["description_original"],
            model_used=model_used,
            generated_at=datetime.now(timezone.utc),
            validation_status="pending",
            needs_human_review=True,
        )


class _FailingLLM:
    """Çeviri ve QA'sı patlayan sağlayıcı (hatalar yutulmamalı)."""

    model = "failing-model"

    def translate_to_tr(self, text):
        raise RuntimeError("429: Kota aşıldı")

    def suggest_remediation(self, advisory):
        raise RuntimeError("bağlantı koptu")

    def generate_qa(self, advisory, model_used):
        raise RuntimeError("500: servis hatası")


class _UnsupportedLLM(_GoodLLM):
    """QA'yı 'kaynakla desteklenmiyor' diye reddeden sağlayıcı (hata değil)."""

    def generate_qa(self, advisory, model_used):
        return None


def test_progress_callback_called_once_per_record():
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "t.db")
        _insert_review(db, "GHSA-1")
        _insert_review(db, "GHSA-2")

        seen = []
        stats = run_enrichment(
            db, _GoodLLM(), provider_name="good", limit=10, on_progress=seen.append
        )
        db.close()

        assert stats["processed"] == 2
        assert [i["index"] for i in seen] == [1, 2]
        assert all(i["total"] == 2 for i in seen)
        assert [i["source_id"] for i in seen] == ["GHSA-1", "GHSA-2"]


def test_progress_reports_success_fields():
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "t.db")
        _insert_review(db, "GHSA-1")
        seen = []
        run_enrichment(db, _GoodLLM(), provider_name="good", limit=5, on_progress=seen.append)
        db.close()

        info = seen[0]
        assert info["translated"] is True
        assert info["remediation"] is True
        assert info["qa_created"] is True
        assert info["errors"] == []
        assert info["translation_snippet"].startswith("TR: ")
        assert "desteklendi" in info["qa_note"]
        assert info["elapsed_s"] >= 0


def test_progress_surfaces_llm_errors_instead_of_swallowing():
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "t.db")
        _insert_review(db, "GHSA-1")
        seen = []
        stats = run_enrichment(
            db, _FailingLLM(), provider_name="bad", limit=5, on_progress=seen.append
        )
        db.close()

        info = seen[0]
        # Hatalar yutulmaz: üçü de raporlanır
        assert len(info["errors"]) == 3
        assert any("Kota" in e for e in info["errors"])
        assert any("bağlantı" in e for e in info["errors"])
        assert any("servis" in e for e in info["errors"])
        # Üretemedikçe zenginleştirme sayımı da artmaz
        assert stats["enriched"] == 0
        assert stats["qa_count"] == 0
        # Üretilen satır hata bilgisini içerir
        line = format_progress_line(info)
        assert "HATA" in line and "Kota" in line


def test_progress_distinguishes_unsupported_qa_from_error():
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "t.db")
        _insert_review(db, "GHSA-1")
        seen = []
        run_enrichment(
            db, _UnsupportedLLM(), provider_name="unsup", limit=5, on_progress=seen.append
        )
        db.close()

        info = seen[0]
        assert info["qa_created"] is False
        assert info["errors"] == []  # hata DEĞİL, model kaynakla desteklemedi
        assert "desteklenmedi" in info["qa_note"]


def test_format_progress_line_is_human_readable():
    info = {
        "index": 1,
        "total": 10,
        "record_id": "github:GHSA-1",
        "source_id": "GHSA-1",
        "translated": True,
        "had_translation_before": False,
        "remediation": False,
        "qa_created": True,
        "qa_note": "kaynakla desteklendi, incelemede",
        "errors": [],
        "elapsed_s": 61.3,
        "translation_snippet": "foo paketinde XSS",
    }
    line = format_progress_line(info)
    assert line.startswith("[1/10] GHSA-1")
    assert "✓çeviri(yeni)" in line
    assert "—önlem" in line
    assert "✓QA" in line
    assert "(61.3s)" in line
    assert "foo paketinde XSS" in line


def test_format_line_distinguishes_existing_translation():
    """'zaten var' ile 'üretilemedi' ayırt edilebilmeli (kullanıcı emin olsun diye)."""
    base = {
        "index": 1,
        "total": 1,
        "record_id": "r",
        "source_id": "GHSA-1",
        "remediation": False,
        "qa_created": False,
        "qa_note": "",
        "errors": [],
        "elapsed_s": 1.0,
        "translation_snippet": "mevcut TR metin",
    }
    yeni = format_progress_line({**base, "translated": True, "had_translation_before": False})
    zaten = format_progress_line({**base, "translated": False, "had_translation_before": True})
    yok = format_progress_line({**base, "translated": False, "had_translation_before": False})
    assert "✓çeviri(yeni)" in yeni
    assert "=çeviri(zaten var)" in zaten
    assert "—çeviri(üretilemedi)" in yok


def test_progress_flags_existing_translation_not_as_new():
    """Önceden çevrilmiş kayıt 'yeni çeviri' gibi sayılmamalı."""
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "t.db")
        _insert_review(db, "GHSA-1")
        # İlk çalıştırma: çeviri üretilir
        seen1 = []
        run_enrichment(db, _GoodLLM(), provider_name="good", limit=5, on_progress=seen1.append)
        assert seen1[0]["translated"] is True
        assert seen1[0]["had_translation_before"] is False
        # İkinci çalıştırma: metin zaten var, yeni çeviri YOK
        seen2 = []
        run_enrichment(db, _GoodLLM(), provider_name="good", limit=5, on_progress=seen2.append)
        db.close()
        assert seen2[0]["translated"] is False
        assert seen2[0]["had_translation_before"] is True


def test_progress_callback_optional_behavior_unchanged():
    """on_progress verilmezse mevcut davranış bozulmamalı."""
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "t.db")
        _insert_review(db, "GHSA-1")
        stats = run_enrichment(db, _GoodLLM(), provider_name="good", limit=5)
        db.close()
        assert stats == {"processed": 1, "enriched": 1, "qa_count": 1}


# ------------------------------------------------------- paralel mod (workers>1)
def test_parallel_workers_produce_same_result_as_sequential():
    def _run(workers):
        with tempfile.TemporaryDirectory() as td:
            db = Database(Path(td) / "t.db")
            _insert_review(db, "GHSA-1")
            _insert_review(db, "GHSA-2")
            stats = run_enrichment(db, _GoodLLM(), provider_name="good", limit=10, workers=workers)
            db.close()
            return stats

    assert _run(1) == _run(3) == {"processed": 2, "enriched": 2, "qa_count": 2}


def test_parallel_persists_translation_to_db():
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "t.db")
        _insert_review(db, "GHSA-1")
        seen = []
        run_enrichment(
            db, _GoodLLM(), provider_name="good", limit=5, workers=3, on_progress=seen.append
        )
        rows = db.list_advisories(quality_status="review", limit=5)
        db.close()
        assert rows[0].description_tr.startswith("TR: ")
        assert seen[0]["translated"] is True


def test_parallel_still_surfaces_all_errors():
    """Paralel modda da hatalar sessizce yutulmamalı."""
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "t.db")
        _insert_review(db, "GHSA-1")
        seen = []
        stats = run_enrichment(
            db, _FailingLLM(), provider_name="bad", limit=5, workers=3, on_progress=seen.append
        )
        db.close()
        assert len(seen[0]["errors"]) == 3
        assert stats["enriched"] == 0
        assert stats["qa_count"] == 0
