"""Veri kalitesi raporu ve metrikleri."""

from __future__ import annotations

from .database import Database
from .schemas import LicenseStatus, QualityReport, QualityStatus


def generate_quality_report(db: Database) -> QualityReport:
    """Veritabanındaki kayıtlara dayalı kalite raporu oluşturur."""
    advisories = db.list_advisories(limit=100000)
    runs = db.list_source_runs(limit=10000)

    total_inserted = len(advisories)
    total_fetched = sum(r.records_fetched for r in runs)
    total_duplicates = sum(r.duplicates for r in runs)
    # Kaynak işlemlerindeki hata sayısı tek doğru kaynaktır; processing_errors
    # tablosu aynı hataların ayrıntılı kaydıdır (çift sayım yapılmaz).
    total_errors = sum(r.errors for r in runs)

    missing_field_count = 0
    unknown_license_count = 0
    translated_count = 0
    by_source: dict[str, dict[str, int]] = {}

    checked_fields = [
        "title",
        "description_original",
        "cve_ids",
        "severity",
        "affected_packages",
        "published_at",
    ]

    for adv in advisories:
        src = adv.source
        by_source.setdefault(
            src,
            {"inserted": 0, "valid": 0, "review": 0, "rejected": 0, "pending": 0},
        )
        by_source[src]["inserted"] += 1

        qs = (
            adv.quality_status.value
            if isinstance(adv.quality_status, QualityStatus)
            else str(adv.quality_status)
        )
        key = qs if qs in ("valid", "review", "rejected", "pending") else "review"
        by_source[src][key] = by_source[src].get(key, 0) + 1

        for field in checked_fields:
            if not getattr(adv, field, None):
                missing_field_count += 1

        if adv.license_status is None or adv.license_status == LicenseStatus.unknown:
            unknown_license_count += 1

        if adv.description_tr:
            translated_count += 1

    total_fields = total_inserted * len(checked_fields)
    missing_field_ratio = (missing_field_count / total_fields) if total_fields else 0.0

    pending_ai_review = db.count_qa(validation_status="pending")
    approved_qa_count = db.count_qa(validation_status="approved")

    # Kaynak kaydı bulunmayan QA örnekleri (orphan)
    advisory_ids = {adv.record_id for adv in advisories}
    orphan_qa_count = 0
    for qa in db.list_qa_pairs(limit=10000):
        if not any(rid in advisory_ids for rid in qa.source_record_ids):
            orphan_qa_count += 1

    report = QualityReport(
        total_fetched=total_fetched,
        total_inserted=total_inserted,
        total_duplicates=total_duplicates,
        total_errors=total_errors,
        missing_field_ratio=round(missing_field_ratio, 4),
        unknown_license_count=unknown_license_count,
        translated_count=translated_count,
        pending_ai_review=pending_ai_review,
        approved_qa_count=approved_qa_count,
        orphan_qa_count=orphan_qa_count,
        by_source=by_source,
    )
    return report
