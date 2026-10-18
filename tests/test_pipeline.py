"""İşlem hattı (pipeline) testleri: sahte bağlayıcı, hata dayanıklılığı."""

from __future__ import annotations

import tempfile
from pathlib import Path

from secdataforge.database import Database
from secdataforge.pipeline import Pipeline


def _adv_dict(source, source_id, cves=None, title="t", desc="d"):
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
        "title": title,
        "description_original": desc,
        "description_tr": None,
        "cve_ids": cves,
        "cwe_ids": None,
        "affected_packages": None,
        "severity": "high",
        "references": None,
        "remediation_tr": None,
        "raw_hash": "h",
        "quality_status": "pending",
        "quality_issues": None,
    }


class _OKConn:
    class Config:
        name = "ok"
        license_status = "allowed"
        license = None

    config = Config()

    def fetch(self, limit=None, cursor=None):
        raws = [
            {"source_id": "S-1", "cves": ["CVE-2024-0001"]},
            {"source_id": "S-2", "cves": ["CVE-2024-0002"]},
        ]
        return _Result(records=raws, errors=[], next_cursor=None)

    def normalize(self, raw):
        return _adv_dict(self.config.name, raw["source_id"], raw["cves"])

    def enrich(self, source_id):
        return None


class _Result:
    def __init__(self, records, errors, next_cursor):
        self.records = records
        self.errors = errors
        self.next_cursor = next_cursor


class _FailingThenOKConn:
    """İlk sayfa hata verir, ikinci sayfa başarır (dayanıklılık testi)."""

    class Config:
        name = "flaky"
        license_status = "allowed"
        license = None

    config = Config()

    def __init__(self):
        self.calls = 0

    def fetch(self, limit=None, cursor=None):
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("geçici ağ hatası")
        return _Result(
            records=[{"source_id": "S-3", "cves": ["CVE-2024-0003"]}],
            errors=[],
            next_cursor=None,
        )

    def normalize(self, raw):
        return _adv_dict(self.config.name, raw["source_id"], raw["cves"])

    def enrich(self, source_id):
        return None


class _BadNormalizeConn:
    """normalize() boş/geçersiz sözlük döndürür; kayıt atılmalı, hataya devam edilmeli."""

    class Config:
        name = "bad"
        license_status = "allowed"
        license = None

    config = Config()

    def fetch(self, limit=None, cursor=None):
        return _Result(
            records=[{"source_id": "S-4", "cves": None}],
            errors=[],
            next_cursor=None,
        )

    def normalize(self, raw):
        return {}

    def enrich(self, source_id):
        return None


def test_pipeline_inserts_and_counts():
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "t.db")
        pipe = Pipeline(db)
        res = pipe.run_source("ok", _OKConn(), limit=10)
        assert res.status.value == "completed"
        assert res.inserted == 2
        assert res.errors == 0
        assert db.count_advisories(source="ok") == 2
        db.close()


def test_pipeline_resilient_to_source_error():
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "t.db")
        pipe = Pipeline(db)
        res = pipe.run_source("flaky", _FailingThenOKConn(), limit=10)
        # İlk sayfa hata verdiği için errors > 0, ikinci sayfadan kayıt eklenebilir
        assert res.errors >= 1
        db.close()


def test_pipeline_skips_malformed_records():
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "t.db")
        pipe = Pipeline(db)
        res = pipe.run_source("bad", _BadNormalizeConn(), limit=10)
        assert res.errors >= 1
        assert db.count_advisories(source="bad") == 0
        db.close()


def test_pipeline_all_sources_continue_on_one_failure():
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "t.db")
        from secdataforge.pipeline import run_pipeline

        results = run_pipeline(
            db,
            {"ok": _OKConn(), "flaky": _FailingThenOKConn()},
            limit=10,
        )
        assert results["ok"].inserted == 2
        assert db.count_advisories(source="ok") == 2
        db.close()
