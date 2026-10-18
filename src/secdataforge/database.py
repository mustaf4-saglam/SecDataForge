"""SQLite tabanlı kalıcı depolama.

Aşağıdaki tablaları tutar:
- raw_records: kaynaklardan alınan ham yanıtlar
- security_advisories: ortak şemaya dönüştürülmüş kayıtlar
- qa_pairs: LLM üretilen soru-cevap örnekleri
- source_runs: kaynak bazlı işlem durumu (izlenebilirlik)
- processing_errors: işlem hataları
- quality_snapshots: kalite rapor anlık görüntüleri

İşlemler idempotent-dir: aynı (source, source_id) çifti tekrar eklenmez.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .schemas import (
    LicenseStatus,
    ProcessingError,
    QAPair,
    QualityReport,
    QualityStatus,
    RawRecord,
    SecurityAdvisory,
    SourceRun,
    SourceRunStatus,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _json_dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _json_load(value: str | None) -> Any:
    if value is None:
        return None
    return json.loads(value)


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt is not None else None


def _parse_iso(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value)


class Database:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False: Streamlit st.cache_resource bağlantıyı farklı
        # thread'lerde yeniden kullanabilir (her rerun ayrı thread'de çalışır).
        # Erişim tek süreç içinde ve kısa işlemlerle sınırlıdır.
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.init_schema()

    def init_schema(self) -> None:
        cur = self.conn.cursor()
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS raw_records (
                raw_id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                source_id TEXT NOT NULL,
                fetched_at TEXT NOT NULL,
                http_status INTEGER NOT NULL,
                raw_payload TEXT NOT NULL,
                etag TEXT,
                raw_hash TEXT,
                UNIQUE(source, source_id)
            );

            CREATE TABLE IF NOT EXISTS security_advisories (
                record_id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                source_id TEXT NOT NULL,
                source_url TEXT,
                license TEXT,
                license_status TEXT,
                collected_at TEXT NOT NULL,
                published_at TEXT,
                modified_at TEXT,
                title TEXT,
                description_original TEXT,
                description_tr TEXT,
                cve_ids TEXT,
                cwe_ids TEXT,
                affected_packages TEXT,
                severity TEXT,
                reference_urls TEXT,
                remediation_tr TEXT,
                raw_hash TEXT,
                quality_status TEXT NOT NULL DEFAULT 'pending',
                quality_issues TEXT,
                UNIQUE(source, source_id)
            );

            CREATE TABLE IF NOT EXISTS qa_pairs (
                qa_id TEXT PRIMARY KEY,
                question TEXT NOT NULL,
                answer TEXT NOT NULL,
                source_record_ids TEXT NOT NULL DEFAULT '[]',
                grounding_fields TEXT NOT NULL DEFAULT '[]',
                model_used TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                validation_status TEXT NOT NULL DEFAULT 'pending',
                needs_human_review INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS source_runs (
                run_id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'running',
                started_at TEXT NOT NULL,
                completed_at TEXT,
                records_fetched INTEGER NOT NULL DEFAULT 0,
                records_inserted INTEGER NOT NULL DEFAULT 0,
                duplicates INTEGER NOT NULL DEFAULT 0,
                errors INTEGER NOT NULL DEFAULT 0,
                error_message TEXT,
                next_cursor TEXT
            );

            CREATE TABLE IF NOT EXISTS processing_errors (
                error_id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                stage TEXT NOT NULL,
                record_id TEXT,
                message TEXT NOT NULL,
                occurred_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS quality_snapshots (
                snapshot_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                report_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_advisories_source ON security_advisories(source);
            CREATE INDEX IF NOT EXISTS idx_advisories_quality ON security_advisories(quality_status);
            CREATE INDEX IF NOT EXISTS idx_qa_validation ON qa_pairs(validation_status);
            CREATE INDEX IF NOT EXISTS idx_runs_source ON source_runs(source);
            """
        )
        self._migrate()
        self.conn.commit()

    def _migrate(self) -> None:
        """Mevcut veritabanları için basit şema geçişleri."""
        cols = {row[1] for row in self.conn.execute("PRAGMA table_info(source_runs)").fetchall()}
        if "next_cursor" not in cols:
            self.conn.execute("ALTER TABLE source_runs ADD COLUMN next_cursor TEXT")

    # ------------------------------------------------------------------ raw
    def insert_raw_record(self, record: RawRecord) -> bool:
        """Ham kaydı ekler. Zaten varsa False döner (idempotent)."""
        try:
            self.conn.execute(
                """
                INSERT OR IGNORE INTO raw_records
                (raw_id, source, source_id, fetched_at, http_status, raw_payload, etag, raw_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.raw_id,
                    record.source,
                    record.source_id,
                    _iso(record.fetched_at),
                    record.http_status,
                    _json_dump(record.raw_payload),
                    record.etag,
                    record.raw_hash,
                ),
            )
            self.conn.commit()
            return self.conn.execute("SELECT changes()").fetchone()[0] > 0
        except sqlite3.IntegrityError:
            return False

    def raw_exists(self, source: str, source_id: str) -> bool:
        cur = self.conn.execute(
            "SELECT 1 FROM raw_records WHERE source = ? AND source_id = ? LIMIT 1",
            (source, source_id),
        )
        return cur.fetchone() is not None

    # ------------------------------------------------------------- advisories
    def insert_advisory(self, advisory: SecurityAdvisory) -> bool:
        """Ortak şema kaydını ekler. Zaten varsa False döner (idempotent)."""
        try:
            self.conn.execute(
                """
                INSERT OR IGNORE INTO security_advisories
                (record_id, source, source_id, source_url, license, license_status,
                 collected_at, published_at, modified_at, title, description_original,
                 description_tr, cve_ids, cwe_ids, affected_packages, severity,
                 reference_urls, remediation_tr, raw_hash, quality_status, quality_issues)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    advisory.record_id,
                    advisory.source,
                    advisory.source_id,
                    str(advisory.source_url) if advisory.source_url else None,
                    advisory.license,
                    advisory.license_status.value if advisory.license_status else None,
                    _iso(advisory.collected_at),
                    _iso(advisory.published_at),
                    _iso(advisory.modified_at),
                    advisory.title,
                    advisory.description_original,
                    advisory.description_tr,
                    _json_dump(advisory.cve_ids),
                    _json_dump(advisory.cwe_ids),
                    _json_dump(advisory.affected_packages),
                    advisory.severity,
                    _json_dump(advisory.references),
                    advisory.remediation_tr,
                    advisory.raw_hash,
                    advisory.quality_status.value
                    if isinstance(advisory.quality_status, QualityStatus)
                    else str(advisory.quality_status),
                    _json_dump(advisory.quality_issues),
                ),
            )
            self.conn.commit()
            return self.conn.execute("SELECT changes()").fetchone()[0] > 0
        except sqlite3.IntegrityError:
            return False

    def advisory_exists(self, source: str, source_id: str) -> bool:
        cur = self.conn.execute(
            "SELECT 1 FROM security_advisories WHERE source = ? AND source_id = ? LIMIT 1",
            (source, source_id),
        )
        return cur.fetchone() is not None

    def get_advisory_by_source_id(self, source: str, source_id: str) -> SecurityAdvisory | None:
        cur = self.conn.execute(
            "SELECT * FROM security_advisories WHERE source = ? AND source_id = ? LIMIT 1",
            (source, source_id),
        )
        row = cur.fetchone()
        return self._row_to_advisory(row) if row else None

    def list_advisories(
        self,
        source: str | None = None,
        quality_status: str | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[SecurityAdvisory]:
        query = "SELECT * FROM security_advisories WHERE 1=1"
        params: list[Any] = []
        if source:
            query += " AND source = ?"
            params.append(source)
        if quality_status:
            query += " AND quality_status = ?"
            params.append(quality_status)
        query += " ORDER BY collected_at DESC"
        if limit is not None:
            query += " LIMIT ? OFFSET ?"
            params.extend([limit, offset])
        cur = self.conn.execute(query, params)
        return [self._row_to_advisory(row) for row in cur.fetchall()]

    def update_quality_status(
        self, record_id: str, status: QualityStatus, issues: list[str] | None = None
    ) -> None:
        self.conn.execute(
            "UPDATE security_advisories SET quality_status = ?, quality_issues = ? WHERE record_id = ?",
            (status.value, _json_dump(issues), record_id),
        )
        self.conn.commit()

    def update_advisory_license(
        self, record_id: str, license_text: str | None, license_status: LicenseStatus | str
    ) -> None:
        """Kaydın lisans alanlarını günceller (lisans politikası iyileştirmesi)."""
        status_value = (
            license_status.value
            if isinstance(license_status, LicenseStatus)
            else str(license_status)
        )
        self.conn.execute(
            "UPDATE security_advisories SET license = ?, license_status = ? WHERE record_id = ?",
            (license_text, status_value, record_id),
        )
        self.conn.commit()

    def update_advisory_enrichment(
        self,
        record_id: str,
        *,
        description_tr: str | None = None,
        remediation_tr: str | None = None,
        quality_status: QualityStatus | None = None,
        quality_issues: list[str] | None = None,
    ) -> None:
        """LLM zenginleştirme çıktılarını (Türkçe metinler) kalıcı hale getirir."""
        sets: list[str] = []
        params: list[Any] = []
        if description_tr is not None:
            sets.append("description_tr = ?")
            params.append(description_tr)
        if remediation_tr is not None:
            sets.append("remediation_tr = ?")
            params.append(remediation_tr)
        if quality_status is not None:
            sets.append("quality_status = ?")
            params.append(quality_status.value)
        if quality_issues is not None:
            sets.append("quality_issues = ?")
            params.append(_json_dump(quality_issues))
        if not sets:
            return
        params.append(record_id)
        self.conn.execute(
            f"UPDATE security_advisories SET {', '.join(sets)} WHERE record_id = ?",
            params,
        )
        self.conn.commit()

    def count_advisories(self, source: str | None = None, quality_status: str | None = None) -> int:
        query = "SELECT COUNT(*) AS c FROM security_advisories WHERE 1=1"
        params: list[Any] = []
        if source:
            query += " AND source = ?"
            params.append(source)
        if quality_status:
            query += " AND quality_status = ?"
            params.append(quality_status)
        cur = self.conn.execute(query, params)
        return cur.fetchone()["c"]

    # ----------------------------------------------------------------- qa
    def insert_qa_pair(self, qa: QAPair) -> bool:
        try:
            self.conn.execute(
                """
                INSERT OR IGNORE INTO qa_pairs
                (qa_id, question, answer, source_record_ids, grounding_fields,
                 model_used, generated_at, validation_status, needs_human_review)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    qa.qa_id,
                    qa.question,
                    qa.answer,
                    _json_dump(qa.source_record_ids),
                    _json_dump(qa.grounding_fields),
                    qa.model_used,
                    _iso(qa.generated_at),
                    qa.validation_status,
                    1 if qa.needs_human_review else 0,
                ),
            )
            self.conn.commit()
            return self.conn.execute("SELECT changes()").fetchone()[0] > 0
        except sqlite3.IntegrityError:
            return False

    def list_qa_pairs(
        self,
        validation_status: str | None = None,
        needs_human_review: bool | None = None,
        limit: int | None = None,
    ) -> list[QAPair]:
        query = "SELECT * FROM qa_pairs WHERE 1=1"
        params: list[Any] = []
        if validation_status:
            query += " AND validation_status = ?"
            params.append(validation_status)
        if needs_human_review is not None:
            query += " AND needs_human_review = ?"
            params.append(1 if needs_human_review else 0)
        query += " ORDER BY generated_at DESC"
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)
        cur = self.conn.execute(query, params)
        return [self._row_to_qa(row) for row in cur.fetchall()]

    def count_qa(self, validation_status: str | None = None) -> int:
        query = "SELECT COUNT(*) AS c FROM qa_pairs WHERE 1=1"
        params: list[Any] = []
        if validation_status:
            query += " AND validation_status = ?"
            params.append(validation_status)
        cur = self.conn.execute(query, params)
        return cur.fetchone()["c"]

    # ------------------------------------------------------------- source runs
    def insert_source_run(self, run: SourceRun) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO source_runs
            (run_id, source, status, started_at, completed_at, records_fetched,
             records_inserted, duplicates, errors, error_message, next_cursor)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run.run_id,
                run.source,
                run.status.value,
                _iso(run.started_at),
                _iso(run.completed_at),
                run.records_fetched,
                run.records_inserted,
                run.duplicates,
                run.errors,
                run.error_message,
                run.next_cursor,
            ),
        )
        self.conn.commit()

    def get_latest_source_run(self, source: str) -> SourceRun | None:
        cur = self.conn.execute(
            "SELECT * FROM source_runs WHERE source = ? ORDER BY started_at DESC LIMIT 1",
            (source,),
        )
        row = cur.fetchone()
        if not row:
            return None
        return SourceRun(
            run_id=row["run_id"],
            source=row["source"],
            status=SourceRunStatus(row["status"]),
            started_at=_parse_iso(row["started_at"]),
            completed_at=_parse_iso(row["completed_at"]),
            records_fetched=row["records_fetched"],
            records_inserted=row["records_inserted"],
            duplicates=row["duplicates"],
            errors=row["errors"],
            error_message=row["error_message"],
            next_cursor=row["next_cursor"],
        )

    def list_source_runs(self, limit: int = 50) -> list[SourceRun]:
        cur = self.conn.execute(
            "SELECT * FROM source_runs ORDER BY started_at DESC LIMIT ?", (limit,)
        )
        return [
            SourceRun(
                run_id=row["run_id"],
                source=row["source"],
                status=SourceRunStatus(row["status"]),
                started_at=_parse_iso(row["started_at"]),
                completed_at=_parse_iso(row["completed_at"]),
                records_fetched=row["records_fetched"],
                records_inserted=row["records_inserted"],
                duplicates=row["duplicates"],
                errors=row["errors"],
                error_message=row["error_message"],
                next_cursor=row["next_cursor"],
            )
            for row in cur.fetchall()
        ]

    # ------------------------------------------------------------ errors
    def insert_processing_error(self, error: ProcessingError) -> None:
        self.conn.execute(
            """
            INSERT OR IGNORE INTO processing_errors
            (error_id, source, stage, record_id, message, occurred_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                error.error_id,
                error.source,
                error.stage,
                error.record_id,
                error.message,
                _iso(error.occurred_at),
            ),
        )
        self.conn.commit()

    def list_errors(self, source: str | None = None, limit: int = 100) -> list[ProcessingError]:
        query = "SELECT * FROM processing_errors WHERE 1=1"
        params: list[Any] = []
        if source:
            query += " AND source = ?"
            params.append(source)
        query += " ORDER BY occurred_at DESC LIMIT ?"
        params.append(limit)
        cur = self.conn.execute(query, params)
        return [
            ProcessingError(
                error_id=row["error_id"],
                source=row["source"],
                stage=row["stage"],
                record_id=row["record_id"],
                message=row["message"],
                occurred_at=_parse_iso(row["occurred_at"]),
            )
            for row in cur.fetchall()
        ]

    # -------------------------------------------------------- quality snapshot
    def save_quality_snapshot(self, snapshot_id: str, report: QualityReport) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO quality_snapshots (snapshot_id, created_at, report_json) VALUES (?, ?, ?)",
            (snapshot_id, _iso(_now()), _json_dump(report.model_dump())),
        )
        self.conn.commit()

    # ----------------------------------------------------------------- helpers
    def _row_to_advisory(self, row: sqlite3.Row) -> SecurityAdvisory:
        return SecurityAdvisory(
            record_id=row["record_id"],
            source=row["source"],
            source_id=row["source_id"],
            source_url=row["source_url"],
            license=row["license"],
            license_status=LicenseStatus(row["license_status"]) if row["license_status"] else None,
            collected_at=_parse_iso(row["collected_at"]),
            published_at=_parse_iso(row["published_at"]),
            modified_at=_parse_iso(row["modified_at"]),
            title=row["title"],
            description_original=row["description_original"],
            description_tr=row["description_tr"],
            cve_ids=_json_load(row["cve_ids"]),
            cwe_ids=_json_load(row["cwe_ids"]),
            affected_packages=_json_load(row["affected_packages"]),
            severity=row["severity"],
            references=_json_load(row["reference_urls"]),
            remediation_tr=row["remediation_tr"],
            raw_hash=row["raw_hash"],
            quality_status=QualityStatus(row["quality_status"])
            if row["quality_status"]
            else QualityStatus.pending,
            quality_issues=_json_load(row["quality_issues"]),
        )

    def _row_to_qa(self, row: sqlite3.Row) -> QAPair:
        return QAPair(
            qa_id=row["qa_id"],
            question=row["question"],
            answer=row["answer"],
            source_record_ids=_json_load(row["source_record_ids"]) or [],
            grounding_fields=_json_load(row["grounding_fields"]) or [],
            model_used=row["model_used"],
            generated_at=_parse_iso(row["generated_at"]),
            validation_status=row["validation_status"],
            needs_human_review=bool(row["needs_human_review"]),
        )

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
