"""Tekrar ayıklama (deduplication) testleri."""

from __future__ import annotations

import tempfile
from pathlib import Path

from secdataforge.database import Database
from secdataforge.pipeline import Pipeline


def _make_advisory_dict(source, source_id, cves, title="t", desc="d"):
    return {
        "record_id": f"{source}:{source_id}",
        "source": source,
        "source_id": source_id,
        "source_url": None,
        "license": None,
        "license_status": "allowed",
        "collected_at": "2024-01-01T00:00:00+00:00",
        "published_at": "2024-01-01T00:00:00+00:00",
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


class _FakeConn:
    class Config:
        name = "fake"
        license_status = "allowed"
        license = None

    config = Config()

    def __init__(self, raws):
        self._raws = raws

    def fetch(self, limit=None, cursor=None):
        raws = self._raws[:limit] if limit else self._raws
        return _FR(records=raws, errors=[], next_cursor=None)

    def normalize(self, raw):
        return _make_advisory_dict(
            self.config.name,
            raw["source_id"],
            raw.get("cves", []),
            raw.get("title", "t"),
            raw.get("desc", "d"),
        )

    def enrich(self, source_id):
        return None


class _FR:
    def __init__(self, records, errors, next_cursor):
        self.records = records
        self.errors = errors
        self.next_cursor = next_cursor


def test_same_source_id_is_duplicate():
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "t.db")
        pipe = Pipeline(db)
        conn = _FakeConn(
            [
                {"source_id": "GHSA-1", "cves": ["CVE-2024-0001"]},
                {"source_id": "GHSA-1", "cves": ["CVE-2024-0001"]},
            ]
        )
        res = pipe.run_source("fake", conn, limit=10)
        assert res.inserted == 1
        assert res.duplicates == 1
        db.close()


def test_same_cve_across_source_is_duplicate():
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "t.db")
        pipe = Pipeline(db)
        conn_a = _FakeConn(
            [
                {"source_id": "GHSA-a", "cves": ["CVE-2024-0001"]},
            ]
        )
        res_a = pipe.run_source("github", conn_a, limit=10)
        assert res_a.inserted == 1
        conn_b = _FakeConn(
            [
                {"source_id": "CVE-2024-0001", "cves": ["CVE-2024-0001"]},
            ]
        )
        res_b = pipe.run_source("osv", conn_b, limit=10)
        assert res_b.inserted == 0
        assert res_b.duplicates == 1
        db.close()


def test_different_cves_not_duplicate():
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "t.db")
        pipe = Pipeline(db)
        conn = _FakeConn(
            [
                {"source_id": "GHSA-a", "cves": ["CVE-2024-0001"]},
                {"source_id": "GHSA-b", "cves": ["CVE-2024-0002"]},
            ]
        )
        res = pipe.run_source("fake", conn, limit=10)
        assert res.inserted == 2
        assert res.duplicates == 0
        db.close()


def test_rerun_is_idempotent():
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "t.db")
        pipe = Pipeline(db)
        conn = _FakeConn(
            [
                {"source_id": "GHSA-1", "cves": ["CVE-2024-0001"]},
            ]
        )
        r1 = pipe.run_source("fake", conn, limit=10)
        r2 = pipe.run_source("fake", conn, limit=10)
        assert r1.inserted == 1
        assert r2.inserted == 0
        assert r2.duplicates == 1
        db.close()
