"""Regresyon testleri: tespit edilen hataların tekrar oluşmamasını doğrular.

Kapsanan hatalar:
- Pipeline limit sayacı çift sayıyordu (limit/2 kayıt işleniyordu).
- Kaynak tamamen başarısız olduğunda durum 'partial' görünüyordu (artık 'failed').
- Kalite raporu hata sayısı çift sayılıyordu (runs + processing_errors).
- --resume imleci kalıcı değildi; artık source_runs.next_cursor saklanır.
- LLM zenginleştirme çıktıları kalıcı hale getirilmiyordu.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from secdataforge.database import Database
from secdataforge.pipeline import Pipeline
from secdataforge.quality import generate_quality_report
from secdataforge.schemas import LicenseStatus, QAPair


def _adv_dict(source, source_id):
    return {
        "record_id": f"{source}:{source_id}",
        "source": source,
        "source_id": source_id,
        "source_url": None,
        "license": None,
        "license_status": "allowed",
        "collected_at": "2024-01-01T00:00:00+00:00",
        "published_at": None,
        "modified_at": None,
        "title": "t",
        "description_original": "d",
        "description_tr": None,
        "cve_ids": None,
        "cwe_ids": None,
        "affected_packages": None,
        "severity": None,
        "references": None,
        "remediation_tr": None,
        "raw_hash": None,
        "quality_status": "pending",
        "quality_issues": None,
    }


class _FR:
    def __init__(self, records, errors, next_cursor):
        self.records = records
        self.errors = errors
        self.next_cursor = next_cursor


class _ManyRecordsConn:
    class Config:
        name = "many"
        license_status = "allowed"
        license = None

    config = Config()

    def fetch(self, limit=None, cursor=None):
        raws = [{"source_id": f"S-{i}"} for i in range(5)]
        return _FR(records=raws, errors=[], next_cursor=None)

    def normalize(self, raw):
        return _adv_dict(self.config.name, raw["source_id"])

    def enrich(self, source_id):
        return None


class _TotalFailureConn:
    class Config:
        name = "broken"
        license_status = "allowed"
        license = None

    config = Config()

    def fetch(self, limit=None, cursor=None):
        return _FR(records=[], errors=["HTTP 403 rate limit exceeded"], next_cursor=None)

    def normalize(self, raw):
        return _adv_dict(self.config.name, "x")

    def enrich(self, source_id):
        return None


class _PagedConn:
    """İki sayfalı sahte kaynak: her sayfa 2 kayıt, imleçler '2' ve None."""

    class Config:
        name = "paged"
        license_status = "allowed"
        license = None

    config = Config()

    def __init__(self):
        self.pages_requested: list[int] = []

    def fetch(self, limit=None, cursor=None):
        page = int(cursor) if cursor else 1
        self.pages_requested.append(page)
        pages = {
            1: [{"source_id": "A"}, {"source_id": "B"}],
            2: [{"source_id": "C"}, {"source_id": "D"}],
        }
        records = pages.get(page, [])
        next_cursor = str(page + 1) if page < 2 else None
        return _FR(records=records, errors=[], next_cursor=next_cursor)

    def normalize(self, raw):
        return _adv_dict(self.config.name, raw["source_id"])

    def enrich(self, source_id):
        return None


class _UnknownLicenseConn:
    """Lisansı henüz doğrulanmamış kaynak (varsayılan politikası unknown)."""

    class Config:
        name = "legacy"
        license_status = "unknown"
        license = None

    config = Config()

    def fetch(self, limit=None, cursor=None):
        return _FR(records=[{"source_id": "L-1"}], errors=[], next_cursor=None)

    def normalize(self, raw):
        return _adv_dict(self.config.name, raw["source_id"])

    def enrich(self, source_id):
        return None


class _VerifiedLicenseConn:
    """Lisansı sonradan doğrulanmış kaynak (ör. GitHub CC-BY-4.0)."""

    class Config:
        name = "legacy"
        license_status = LicenseStatus.allowed
        license = "CC-BY-4.0"

    config = Config()

    def fetch(self, limit=None, cursor=None):
        return _FR(records=[], errors=[], next_cursor=None)

    def normalize(self, raw):
        return _adv_dict(self.config.name, raw["source_id"])

    def enrich(self, source_id):
        return None


def test_limit_is_respected():
    """limit=N ise en fazla N kayıt işlenmeli (eski hata: N/2)."""
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "t.db")
        res = Pipeline(db).run_source("many", _ManyRecordsConn(), limit=3)
        assert res.fetched == 3
        assert res.inserted == 3
        assert db.count_advisories(source="many") == 3
        db.close()


def test_total_failure_status_is_failed():
    """Hiç kayıt eklenemediğinde ve hata varsa durum 'failed' olmalı."""
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "t.db")
        res = Pipeline(db).run_source("broken", _TotalFailureConn(), limit=10)
        assert res.status.value == "failed"
        db.close()


def test_license_policy_heals_existing_records():
    """Sonradan verilen lisans kararı (ör. GitHub CC-BY-4.0) eski kayıtları iyileştirir."""
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "t.db")
        pipe = Pipeline(db)

        # 1. Kayıt, lisansı bilinmeyen bir bağlayıcıyla toplanır -> review
        pipe.run_source("legacy", _UnknownLicenseConn(), limit=1)
        adv = db.list_advisories(source="legacy")[0]
        assert adv.quality_status.value == "review"
        assert adv.license_status.value == "unknown"

        # 2. Politikası tanımsız (unknown) bağlayıcı kayda dokunmamalı
        assert pipe.apply_license_policy(adv, _UnknownLicenseConn()) is False
        assert adv.license_status.value == "unknown"

        # 3. Lisans doğrulanır (ör. CC-BY-4.0) ve mevcut kayda uygulanır
        assert pipe.apply_license_policy(adv, _VerifiedLicenseConn()) is True
        db.update_advisory_license(adv.record_id, adv.license, adv.license_status)
        status, issues = pipe._validate_advisory(adv)
        db.update_quality_status(adv.record_id, status, issues)

        healed = db.get_advisory_by_source_id("legacy", adv.source_id)
        assert healed is not None
        assert healed.quality_status.value == "valid"
        assert healed.license == "CC-BY-4.0"
        assert healed.license_status.value == "allowed"
        db.close()


def test_quality_report_errors_not_double_counted():
    """total_errors yalnızca source_runs hata sayılarının toplamı olmalı."""
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "t.db")
        Pipeline(db).run_source("broken", _TotalFailureConn(), limit=10)
        report = generate_quality_report(db)
        run_errors = sum(r.errors for r in db.list_source_runs(limit=100))
        assert report.total_errors == run_errors == 1
        db.close()


def test_resume_continues_from_saved_cursor():
    """--resume, son işlemin kaydettiği imleçten devam etmeli."""
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "t.db")
        conn = _PagedConn()
        pipe = Pipeline(db)

        # İlk çalıştırma: limit=2 -> yalnızca 1. sayfa; imleç '2' kaydedilir
        r1 = pipe.run_source("paged", conn, limit=2)
        assert r1.inserted == 2
        last = db.get_latest_source_run("paged")
        assert last is not None and last.next_cursor == "2"

        # İkinci çalıştırma: resume -> 2. sayfadan devam eder (yeni kayıtlar C, D)
        r2 = pipe.run_source("paged", conn, limit=2, resume=True)
        assert r2.inserted == 2
        ids = {a.source_id for a in db.list_advisories(source="paged")}
        assert {"A", "B", "C", "D"} <= ids
        assert conn.pages_requested[-1] == 2
        db.close()


def test_enrichment_is_persisted_and_qa_stored():
    """LLM çıktıları (description_tr, remediation_tr) ve QA çifti kalıcı olmalı."""
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "t.db")
        Pipeline(db).run_source("many", _ManyRecordsConn(), limit=1)

        adv = db.list_advisories(source="many")[0]
        db.update_advisory_enrichment(
            adv.record_id,
            description_tr="Türkçe çeviri metni",
            remediation_tr="Önlem metni",
            quality_issues=["insan incelemesi gerekli"],
        )
        qa = QAPair(
            qa_id="qa:test:0001",
            question="Soru?",
            answer="Cevap.",
            source_record_ids=[adv.record_id],
            grounding_fields=["description_original"],
            model_used="test:model",
            generated_at="2024-01-01T00:00:00+00:00",
        )
        assert db.insert_qa_pair(qa) is True
        assert db.insert_qa_pair(qa) is False  # idempotent

        reloaded = db.get_advisory_by_source_id("many", adv.source_id)
        assert reloaded is not None
        assert reloaded.description_tr == "Türkçe çeviri metni"
        assert reloaded.remediation_tr == "Önlem metni"
        assert db.count_qa(validation_status="pending") == 1
        db.close()
