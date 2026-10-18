"""Dışa aktarma (JSONL/CSV) testleri."""

from __future__ import annotations

import csv
import json
import tempfile
from pathlib import Path

from secdataforge.database import Database
from secdataforge.exporters import (
    QA_FIELDNAMES,
    export_csv,
    export_jsonl,
    export_qa_csv,
    export_qa_jsonl,
)
from secdataforge.schemas import SecurityAdvisory


def _insert_advisory(db, source, source_id, quality="valid", cves=None):
    adv = SecurityAdvisory(
        record_id=f"{source}:{source_id}",
        source=source,
        source_id=source_id,
        collected_at="2024-01-01T00:00:00+00:00",
        published_at="2024-01-01T00:00:00+00:00",
        title=f"Title {source_id}",
        description_original=f"Desc {source_id}",
        cve_ids=cves,
        severity="high",
        quality_status=quality,
    )
    db.insert_advisory(adv)


def test_export_jsonl_writes_valid_records():
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "out.jsonl"
        db = Database(Path(td) / "t.db")
        _insert_advisory(db, "github", "GHSA-1", quality="valid", cves=["CVE-1"])
        _insert_advisory(db, "github", "GHSA-2", quality="review", cves=None)
        db.close()
        n = export_jsonl(Database(Path(td) / "t.db"), out, quality_status="valid")
        assert n == 1
        lines = out.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        obj = json.loads(lines[0])
        assert obj["record_id"] == "github:GHSA-1"
        assert obj["cve_ids"] == "CVE-1"


def test_export_csv_writes_valid_records():
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "out.csv"
        db = Database(Path(td) / "t.db")
        _insert_advisory(db, "osv", "CVE-1", quality="valid", cves=["CVE-1"])
        _insert_advisory(db, "osv", "CVE-2", quality="rejected", cves=None)
        db.close()
        n = export_csv(Database(Path(td) / "t.db"), out, quality_status="valid")
        assert n == 1
        with out.open(encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            rows = list(reader)
        assert len(rows) == 1
        assert rows[0]["record_id"] == "osv:CVE-1"


def test_export_empty_writes_header_only():
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "out.csv"
        db = Database(Path(td) / "t.db")
        db.close()
        n = export_csv(Database(Path(td) / "t.db"), out, quality_status="valid")
        assert n == 0
        text = out.read_text(encoding="utf-8")
        assert "record_id" in text


# ------------------------------------------------- AI soru-cevap (QA) dışa aktarım
def _insert_qa(db, qa_id, record_id="github:GHSA-1", status="pending"):
    from datetime import datetime, timezone

    from secdataforge.schemas import QAPair

    db.insert_qa_pair(
        QAPair(
            qa_id=qa_id,
            question=f"Soru {qa_id}?",
            answer=f"Cevap {qa_id}.",
            source_record_ids=[record_id],
            grounding_fields=["description_original"],
            model_used="evren:deepseek-v4.1-flash",
            generated_at=datetime.now(timezone.utc),
            validation_status=status,
            needs_human_review=True,
        )
    )


def _insert_licensed_advisory(db):
    from secdataforge.schemas import LicenseStatus

    adv = SecurityAdvisory(
        record_id="github:GHSA-1",
        source="github",
        source_id="GHSA-1",
        collected_at="2024-01-01T00:00:00+00:00",
        published_at="2024-01-01T00:00:00+00:00",
        title="XSS in foo",
        description_original="Reflected XSS.",
        cve_ids=["CVE-2024-0001"],
        severity="high",
        quality_status="valid",
        license="CC-BY-4.0",
        license_status=LicenseStatus.allowed,
    )
    db.insert_advisory(adv)


def test_export_qa_jsonl_writes_rows_with_source_context():
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "qa.jsonl"
        db = Database(Path(td) / "t.db")
        _insert_licensed_advisory(db)
        _insert_qa(db, "qa-1")
        db.close()

        n = export_qa_jsonl(Database(Path(td) / "t.db"), out)
        assert n == 1
        obj = json.loads(out.read_text(encoding="utf-8").strip())
        assert obj["question"] == "Soru qa-1?"
        assert obj["model_used"] == "evren:deepseek-v4.1-flash"
        assert obj["validation_status"] == "pending"
        assert obj["needs_human_review"] == "true"
        # Kaynak bağlamı: lisans ve CVE izlenebilir
        assert obj["source"] == "github"
        assert obj["source_id"] == "GHSA-1"
        assert obj["cve_ids"] == "CVE-2024-0001"
        assert obj["license"] == "CC-BY-4.0"
        assert obj["license_status"] == "allowed"


def test_export_qa_csv_fixed_field_order():
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "qa.csv"
        db = Database(Path(td) / "t.db")
        _insert_licensed_advisory(db)
        _insert_qa(db, "qa-1")
        db.close()

        n = export_qa_csv(Database(Path(td) / "t.db"), out)
        assert n == 1
        with out.open(encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            rows = list(reader)
        assert reader.fieldnames == QA_FIELDNAMES
        assert rows[0]["question"] == "Soru qa-1?"
        assert rows[0]["grounding_fields"] == "description_original"


def test_export_qa_filters_by_validation_status():
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "qa.jsonl"
        db = Database(Path(td) / "t.db")
        _insert_licensed_advisory(db)
        _insert_qa(db, "qa-p", status="pending")
        _insert_qa(db, "qa-a", status="approved")
        db.close()

        n = export_qa_jsonl(Database(Path(td) / "t.db"), out, validation_status="approved")
        assert n == 1
        obj = json.loads(out.read_text(encoding="utf-8").strip())
        assert obj["qa_id"] == "qa-a"


def test_export_qa_orphan_without_source_keeps_empty_context():
    """Kaynak kaydı olmayan QA boş bağlamla çıkar (patlamaz)."""
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "qa.jsonl"
        db = Database(Path(td) / "t.db")
        _insert_qa(db, "qa-orphan", record_id="github:YOK")
        db.close()

        n = export_qa_jsonl(Database(Path(td) / "t.db"), out)
        assert n == 1
        obj = json.loads(out.read_text(encoding="utf-8").strip())
        assert obj["source"] == ""
        assert obj["license"] == ""
