"""Veri şeması (Pydantic modelleri) birim testleri."""

from datetime import datetime, timezone

from secdataforge.schemas import (
    LicenseStatus,
    QAPair,
    QualityStatus,
    RawRecord,
    SecurityAdvisory,
    SourceRunStatus,
)


def test_security_advisory_required_fields():
    adv = SecurityAdvisory(
        record_id="rec-1",
        source="github",
        source_id="GHSA-xxxx",
        collected_at=datetime.now(timezone.utc),
    )
    assert adv.record_id == "rec-1"
    assert adv.source == "github"
    assert adv.source_id == "GHSA-xxxx"
    assert adv.quality_status == QualityStatus.pending
    assert adv.description_tr is None


def test_security_advisory_full():
    adv = SecurityAdvisory(
        record_id="rec-2",
        source="osv",
        source_id="CVE-2024-0001",
        source_url="https://osv.dev/vulnerability/CVE-2024-0001",
        license="CC0",
        license_status=LicenseStatus.allowed,
        collected_at=datetime.now(timezone.utc),
        published_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        modified_at=datetime(2024, 1, 2, tzinfo=timezone.utc),
        title="Test advisory",
        description_original="Original description.",
        description_tr="Türkçe açıklama.",
        cve_ids=["CVE-2024-0001"],
        cwe_ids=["CWE-79"],
        affected_packages=["foo@1.0.0"],
        severity="high",
        references=["https://example.com/ref"],
        remediation_tr="Güncelleme yapın.",
        raw_hash="abc123",
        quality_status=QualityStatus.valid,
    )
    assert adv.cve_ids == ["CVE-2024-0001"]
    assert adv.severity == "high"
    assert adv.quality_status == QualityStatus.valid


def test_dedupe_key_cve_based():
    adv = SecurityAdvisory(
        record_id="r1",
        source="github",
        source_id="GHSA-a",
        collected_at=datetime.now(timezone.utc),
        cve_ids=["CVE-2024-0001"],
    )
    assert adv.dedupe_key() == "cve:CVE-2024-0001"


def test_dedupe_key_source_based():
    adv = SecurityAdvisory(
        record_id="r1",
        source="osv",
        source_id="OSV-1",
        collected_at=datetime.now(timezone.utc),
    )
    assert adv.dedupe_key() == "source:osv:OSV-1"


def test_qa_pair_defaults():
    qa = QAPair(
        qa_id="qa-1",
        question="Nedir?",
        answer="Bir zafiyettir.",
        source_record_ids=["rec-1"],
        grounding_fields=["description_original"],
        model_used="test-model",
        generated_at=datetime.now(timezone.utc),
    )
    assert qa.validation_status == "pending"
    assert qa.needs_human_review is True


def test_quality_status_enum():
    assert QualityStatus.pending == "pending"
    assert QualityStatus.valid == "valid"
    assert QualityStatus.review == "review"
    assert QualityStatus.rejected == "rejected"


def test_license_status_enum():
    assert LicenseStatus.unknown == "unknown"
    assert LicenseStatus.allowed == "allowed"
    assert LicenseStatus.restricted == "restricted"


def test_source_run_status_enum():
    assert SourceRunStatus.running == "running"
    assert SourceRunStatus.completed == "completed"
    assert SourceRunStatus.failed == "failed"
    assert SourceRunStatus.partial == "partial"


def test_raw_record():
    raw = RawRecord(
        raw_id="raw-1",
        source="github",
        source_id="GHSA-1",
        fetched_at=datetime.now(timezone.utc),
        http_status=200,
        raw_payload={"id": "GHSA-1"},
        raw_hash="hash",
    )
    assert raw.raw_payload == {"id": "GHSA-1"}
    assert raw.http_status == 200
