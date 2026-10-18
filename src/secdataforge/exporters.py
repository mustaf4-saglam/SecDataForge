"""Veri dışa aktarma: JSONL ve CSV.

Varsayılan olarak sadece ``quality_status == valid`` kayıtları dışa aktarılır.
İnceleme bekleyen kayıtlar dışa aktarılamaz (lisans/kalite onayı gerekir).
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from .database import Database
from .schemas import QAPair, QualityReport, SecurityAdvisory

FIELDNAMES = [
    "record_id",
    "source",
    "source_id",
    "source_url",
    "license",
    "license_status",
    "collected_at",
    "published_at",
    "modified_at",
    "title",
    "description_original",
    "description_tr",
    "cve_ids",
    "cwe_ids",
    "affected_packages",
    "severity",
    "reference_urls",
    "remediation_tr",
    "raw_hash",
    "quality_status",
    "quality_issues",
]

# AI soru-cevap çiftleri (LLM eğitim/eval için); sabit alan sırası
QA_FIELDNAMES = [
    "qa_id",
    "question",
    "answer",
    "source_record_ids",
    "grounding_fields",
    "model_used",
    "generated_at",
    "validation_status",
    "needs_human_review",
    # Kaynak bağlamı (lisans/filtreleme için — izlenebilirlik)
    "source",
    "source_id",
    "cve_ids",
    "license",
    "license_status",
]


def _advisory_row(adv: SecurityAdvisory) -> dict[str, Any]:
    return {
        "record_id": adv.record_id,
        "source": adv.source,
        "source_id": adv.source_id,
        "source_url": str(adv.source_url) if adv.source_url else "",
        "license": adv.license or "",
        "license_status": adv.license_status.value if adv.license_status else "",
        "collected_at": adv.collected_at.isoformat() if adv.collected_at else "",
        "published_at": adv.published_at.isoformat() if adv.published_at else "",
        "modified_at": adv.modified_at.isoformat() if adv.modified_at else "",
        "title": adv.title or "",
        "description_original": adv.description_original or "",
        "description_tr": adv.description_tr or "",
        "cve_ids": "|".join(adv.cve_ids or []),
        "cwe_ids": "|".join(adv.cwe_ids or []),
        "affected_packages": "|".join(adv.affected_packages or []),
        "severity": adv.severity or "",
        "reference_urls": "|".join(adv.references or []),
        "remediation_tr": adv.remediation_tr or "",
        "raw_hash": adv.raw_hash or "",
        "quality_status": adv.quality_status.value
        if isinstance(adv.quality_status, str)
        else str(adv.quality_status),
        "quality_issues": "|".join(adv.quality_issues or []),
    }


def export_jsonl(
    db: Database,
    output_path: str | Path,
    source: str | None = None,
    quality_status: str = "valid",
    limit: int | None = None,
) -> int:
    """Kayıtları JSONL olarak yazar. Yazılan kayıt sayısını döndürür."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    advisories = db.list_advisories(source=source, quality_status=quality_status, limit=limit)
    count = 0
    with output_path.open("w", encoding="utf-8") as fh:
        for adv in advisories:
            fh.write(json.dumps(_advisory_row(adv), ensure_ascii=False, sort_keys=True))
            fh.write("\n")
            count += 1
    return count


def export_csv(
    db: Database,
    output_path: str | Path,
    source: str | None = None,
    quality_status: str = "valid",
    limit: int | None = None,
) -> int:
    """Kayıtları CSV olarak yazar. Yazılan kayıt sayısını döndürür."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    advisories = db.list_advisories(source=source, quality_status=quality_status, limit=limit)
    if not advisories:
        with output_path.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=FIELDNAMES)
            writer.writeheader()
        return 0

    count = 0
    with output_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES)
        writer.writeheader()
        for adv in advisories:
            writer.writerow(_advisory_row(adv))
            count += 1
    return count


# --------------------------------------------------- AI soru-cevap dışa aktarım
def _qa_row(qa: QAPair, adv_index: dict[str, SecurityAdvisory]) -> dict[str, Any]:
    """QA çiftini sabit alanlar + ilk kaynak kaydının bağlamıyla satıra çevirir."""
    first_id = (qa.source_record_ids or [None])[0]
    adv = adv_index.get(first_id) if first_id else None
    return {
        "qa_id": qa.qa_id,
        "question": qa.question,
        "answer": qa.answer,
        "source_record_ids": "|".join(qa.source_record_ids or []),
        "grounding_fields": "|".join(qa.grounding_fields or []),
        "model_used": qa.model_used,
        "generated_at": qa.generated_at.isoformat() if qa.generated_at else "",
        "validation_status": qa.validation_status,
        "needs_human_review": "true" if qa.needs_human_review else "false",
        # Kaynak bağlamı (izinli/izin verilmeyen lisans filtresi için)
        "source": adv.source if adv else "",
        "source_id": adv.source_id if adv else "",
        "cve_ids": "|".join(adv.cve_ids or []) if adv else "",
        "license": (adv.license or "") if adv else "",
        "license_status": adv.license_status.value if adv and adv.license_status else "",
    }


def _load_advisory_index(db: Database) -> dict[str, SecurityAdvisory]:
    """QA'ların kaynak kayıtlarını kimliklerine göre hızlı erişim için indeksler."""
    return {adv.record_id: adv for adv in db.list_advisories(limit=None)}


def export_qa_jsonl(
    db: Database,
    output_path: str | Path,
    validation_status: str | None = None,
    limit: int | None = None,
) -> int:
    """AI soru-cevap çiftlerini JSONL olarak yazar (LLM eğitim/eval için)."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    qa_pairs = db.list_qa_pairs(validation_status=validation_status, limit=limit)
    adv_index = _load_advisory_index(db)
    count = 0
    with output_path.open("w", encoding="utf-8") as fh:
        for qa in qa_pairs:
            fh.write(json.dumps(_qa_row(qa, adv_index), ensure_ascii=False, sort_keys=True))
            fh.write("\n")
            count += 1
    return count


def export_qa_csv(
    db: Database,
    output_path: str | Path,
    validation_status: str | None = None,
    limit: int | None = None,
) -> int:
    """AI soru-cevap çiftlerini CSV olarak yazar (sabit alan sırası)."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    qa_pairs = db.list_qa_pairs(validation_status=validation_status, limit=limit)
    adv_index = _load_advisory_index(db)
    count = 0
    with output_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=QA_FIELDNAMES)
        writer.writeheader()
        for qa in qa_pairs:
            writer.writerow(_qa_row(qa, adv_index))
            count += 1
    return count


def export_quality_report(
    report: QualityReport,
    output_path: str | Path,
) -> None:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(report.model_dump(), fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")
