"""İşlem hattı (pipeline) orkestrasyonu.

Aşamalar:
1. Kaynaktan veri al (connector.fetch)
2. Ham yanıtı ve kaynak metaverisini kaydet (raw_records)
3. Lisans ve yeniden kullanım politikasını kontrol et
4. Ortak şemaya dönüştür (connector.normalize)
5. Kaynak kimliği / CVE / içerik özeti ile tekrarları ayıkla
6. Eksik alan, tür, tarih ve tutarlılık kontrolleri
7. İsteğe bağlı Türkçeleştirme ve LLM zenginleştirmesi
8. Üretilen metinlerin dayanağı ve şema uyumu denetimi
9. Başarısız/şüpheli kayıtları inceleme kuyruğuna aktar
10. Onaylanmış kayıtları dışa aktar (exporters)
11. Veri kalitesi raporu oluştur

Bir kaynaktaki hata tüm hatayı çökmemesini sağlar; işlem devam ettirilebilir.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

from .config import settings
from .database import Database
from .schemas import (
    LicenseStatus,
    ProcessingError,
    QualityStatus,
    RawRecord,
    SecurityAdvisory,
    SourceRun,
    SourceRunStatus,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _make_raw_id(source: str, source_id: str) -> str:
    return f"{source}:{source_id}:{uuid.uuid4().hex[:8]}"


def _hash_payload(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class PipelineResult:
    """Bir kaynak için işlem hattı sonucu."""

    def __init__(self, source: str) -> None:
        self.source = source
        self.fetched = 0
        self.inserted = 0
        self.duplicates = 0
        self.errors = 0
        self.error_messages: list[str] = []
        self.status: SourceRunStatus = SourceRunStatus.completed


class Pipeline:
    def __init__(self, db: Database) -> None:
        self.db = db
        self._llm = None  # opsiyonel, sonra bağlanır
        # Şeffaflık: son LLM çağrısında yakalanan hatalar (sessizce yutulmaz)
        self.llm_errors: list[str] = []

    # ------------------------------------------------------------------ run
    def run_source(
        self,
        source_name: str,
        connector: Any,
        limit: int | None = None,
        cursor: Any = None,
        resume: bool = False,
        full_history: bool = False,
        since: str | None = None,
    ) -> PipelineResult:
        """Tek bir kaynağın tüm işlem hattını çalıştırır."""
        limit = limit or settings.default_record_limit
        result = PipelineResult(source=source_name)

        # full_history: imleci yok say, baştan başla (resume'i devre dışı bırakır)
        next_cursor: Any = cursor
        use_resume = resume and not full_history
        if use_resume and next_cursor is None:
            last_run = self.db.get_latest_source_run(source_name)
            if last_run is not None and last_run.next_cursor is not None:
                next_cursor = last_run.next_cursor

        run_id = f"{source_name}:{uuid.uuid4().hex[:8]}"
        run = SourceRun(
            run_id=run_id,
            source=source_name,
            status=SourceRunStatus.running,
            started_at=_now(),
        )
        self.db.insert_source_run(run)

        # since filtresi için datetime objesi hazırla (UTC aware)
        since_dt = None
        if since:
            try:
                since_dt = datetime.fromisoformat(since)
                if since_dt.tzinfo is None:
                    since_dt = since_dt.replace(tzinfo=timezone.utc)
            except ValueError:
                result.errors += 1
                result.error_messages.append(
                    f"Geçersiz --since formatı (YYYY-MM-DD bekleniyor): {since}"
                )

        try:
            # Mevcut zafiyet kimliklerini (cross-source dedupe için) yükle
            seen_cves: set[str] = self._load_seen_cves()
            seen_keys: set[str] = set()

            while True:
                if result.fetched >= limit:
                    break
                remaining = limit - result.fetched
                try:
                    fetch_result = connector.fetch(limit=remaining, cursor=next_cursor)
                except Exception as exc:  # bir sayfa hata verirse hatayı kaydetmeye devam et
                    result.errors += 1
                    result.error_messages.append(f"fetch sayfa hatası: {exc}")
                    break

                result.error_messages.extend(fetch_result.errors)
                result.errors += len(fetch_result.errors)

                for raw in fetch_result.records:
                    if result.fetched >= limit:
                        break
                    result.fetched += 1
                    try:
                        self._process_one(
                            connector,
                            raw,
                            seen_cves,
                            seen_keys,
                            result,
                            since_dt=since_dt,
                        )
                    except Exception as exc:  # tek bir kayıt hata verirse hatayı kaydet, devam et
                        result.errors += 1
                        result.error_messages.append(f"kayıt işleme hatası: {exc}")
                        self._log_error(source_name, "process", None, str(exc))

                next_cursor = fetch_result.next_cursor
                if not fetch_result.records or next_cursor is None:
                    break

            if result.errors > 0 and result.inserted == 0:
                result.status = SourceRunStatus.failed
            elif result.errors > 0:
                result.status = SourceRunStatus.partial
            else:
                result.status = SourceRunStatus.completed

        except Exception as exc:  # kaynak genel hatası
            result.status = SourceRunStatus.failed
            result.errors += 1
            result.error_messages.append(str(exc))
            self._log_error(source_name, "source", None, str(exc))
        finally:
            run.completed_at = _now()
            run.status = result.status
            run.records_fetched = result.fetched
            run.records_inserted = result.inserted
            run.duplicates = result.duplicates
            run.errors = result.errors
            run.error_message = "; ".join(result.error_messages) if result.error_messages else None
            run.next_cursor = str(next_cursor) if next_cursor is not None else None
            self.db.insert_source_run(run)

        return result

    # ------------------------------------------------------------ tek kayıt
    def _process_one(
        self,
        connector: Any,
        raw: dict[str, Any],
        seen_cves: set[str],
        seen_keys: set[str],
        result: PipelineResult,
        since_dt: datetime | None = None,
    ) -> None:
        source = connector.config.name

        # Kaynak kimliğini çıkar (GHSA / CVE / id)
        source_id = str(
            raw.get("ghsa_id") or raw.get("id") or raw.get("alias") or raw.get("source_id") or ""
        )
        if not source_id:
            source_id = f"auto:{_hash_payload(raw)[:12]}"

        # 2. Ham yanıtı kaydet
        raw_record = RawRecord(
            raw_id=_make_raw_id(source, source_id),
            source=source,
            source_id=source_id,
            fetched_at=_now(),
            http_status=200,
            raw_payload=raw,
            etag=None,
            raw_hash=_hash_payload(raw),
        )
        self.db.insert_raw_record(raw_record)

        # 4. Ortak şemaya dönüştür
        advisory_dict = connector.normalize(raw)
        advisory_dict["collected_at"] = _now().isoformat()
        advisory_dict["raw_hash"] = raw_record.raw_hash

        # 3. Lisans kontrolü
        self._apply_license_check(connector, advisory_dict)

        # Nesne haline getir ve şemayı doğrula
        try:
            advisory = SecurityAdvisory(**advisory_dict)
        except Exception as exc:
            result.errors += 1
            self._log_error(source, "normalize", source_id, f"şema doğrulama hatası: {exc}")
            return

        # --since filtresi: published_at since_dt'den eskiyse atla
        if since_dt is not None and advisory.published_at is not None:
            if advisory.published_at < since_dt:
                result.duplicates += 1  # sayım ama eklenmez
                return

        # 5. Tekrar ayıklama (aynı kaynak + cross-source CVE)
        dkey = advisory.dedupe_key()
        if dkey in seen_keys:
            result.duplicates += 1
            return
        advisory_cves = set(advisory.cve_ids or [])
        if advisory_cves and advisory_cves & seen_cves:
            result.duplicates += 1
            return

        # 6. Kalite kontrolleri (lisans durumu da burada değerlendirilir)
        status, issues = self._validate_advisory(advisory)

        # 9. Şüpheli kayıtlar inceleme kuyruğuna: quality_status=review + quality_issues
        #    (bunlar hata değildir; hata metriklerine karıştırılmaz)
        advisory.quality_status = status
        advisory.quality_issues = issues

        # Veritabanına idempotent ekle
        inserted = self.db.insert_advisory(advisory)
        if inserted:
            result.inserted += 1
            seen_keys.add(dkey)
            seen_cves.update(advisory_cves)
        else:
            result.duplicates += 1

    # -------------------------------------------------------- yardımcı aşamalar
    def _apply_license_check(self, connector: Any, advisory_dict: dict[str, Any]) -> None:
        """Lisans durumunu ayarlar; bilinmeyen/kısıtlı -> inceleme kuyruğu."""
        status = getattr(connector.config, "license_status", LicenseStatus.unknown)
        license_text = getattr(connector.config, "license", None)
        advisory_dict["license"] = license_text
        advisory_dict["license_status"] = (
            status.value if isinstance(status, LicenseStatus) else str(status)
        )

    def apply_license_policy(self, advisory: SecurityAdvisory, connector: Any) -> bool:
        """Bağlayıcıda tanımlı güncel lisans politikasını mevcut kayda uygular.

        Kaynak için lisans kararı sonradan verildiğinde (ör. GitHub Advisory
        Database CC-BY-4.0) eski kayıtları iyileştirmek için kullanılır.
        Politika tanımlı değilse (unknown) kayda dokunulmaz. Kayıt değiştiyse
        True döner; çağıran taraf veritabanını günceller.
        """
        status = getattr(connector.config, "license_status", LicenseStatus.unknown)
        license_text = getattr(connector.config, "license", None)
        if not license_text or status == LicenseStatus.unknown:
            return False
        changed = advisory.license != license_text or advisory.license_status != status
        if changed:
            advisory.license = license_text
            advisory.license_status = status
        return changed

    def _validate_advisory(self, advisory: SecurityAdvisory) -> tuple[QualityStatus, list[str]]:
        """Eksik alan, tür, tarih ve tutarlılık kontrolleri."""
        issues: list[str] = []

        if not advisory.record_id:
            issues.append("record_id eksik")
        if not advisory.source:
            issues.append("source eksik")
        if not advisory.source_id:
            issues.append("source_id eksik")
        if not advisory.collected_at:
            issues.append("collected_at eksik")

        # Tür kontrolleri
        if advisory.cve_ids is not None and not isinstance(advisory.cve_ids, list):
            issues.append("cve_ids liste değil")
        if advisory.cwe_ids is not None and not isinstance(advisory.cwe_ids, list):
            issues.append("cwe_ids liste değil")
        if advisory.affected_packages is not None and not isinstance(
            advisory.affected_packages, list
        ):
            issues.append("affected_packages liste değil")
        if advisory.references is not None and not isinstance(advisory.references, list):
            issues.append("references liste değil")

        # Tarih tutarlılığı: published_at <= modified_at
        if advisory.published_at and advisory.modified_at:
            try:
                if advisory.published_at > advisory.modified_at:
                    issues.append("published_at modified_at'den sonrası")
            except TypeError:
                # Bilinçli/bilinçsiz zaman dilimi karışıklığı: karşılaştırma yapılamaz
                issues.append("tarih karşılaştırması belirsiz (zaman dilimi)")

        # İçerik zenginliği: başlık ve açıklama ikisi de yoksa düşük kalite
        if not advisory.title and not advisory.description_original:
            issues.append("başlık ve açıklama eksik")

        # Bilinmeyen/kısıtlı lisanslı kayıtlar dışa aktarılmaz, incelemeye gider.
        if advisory.license_status is None or advisory.license_status in (
            LicenseStatus.unknown,
            LicenseStatus.restricted,
        ):
            issues.append("lisans durumu belirsiz veya kısıtlı")

        status = QualityStatus.review if issues else QualityStatus.valid
        return status, issues or None

    def _load_seen_cves(self) -> set[str]:
        seen: set[str] = set()
        advisories = self.db.list_advisories(limit=10000)
        for adv in advisories:
            for cve in adv.cve_ids or []:
                seen.add(cve)
        return seen

    def _log_error(self, source: str, stage: str, record_id: str | None, message: str) -> None:
        error = ProcessingError(
            error_id=f"err:{uuid.uuid4().hex[:8]}",
            source=source,
            stage=stage,
            record_id=record_id,
            message=message,
            occurred_at=_now(),
        )
        self.db.insert_processing_error(error)

    # ------------------------------------------------------------- LLM (opsiyonel)
    def attach_llm(self, llm: Any) -> None:
        self._llm = llm

    def enrich_with_llm(self, advisory: SecurityAdvisory) -> SecurityAdvisory:
        """İsteğe bağlı LLM zenginleştirmesi (Türkçe çeviri, önlem, QA)."""
        if self._llm is None:
            return advisory
        # Türkçe çeviri
        try:
            tr = self._llm.translate_to_tr(advisory.description_original or advisory.title or "")
            if tr:
                advisory.description_tr = tr
        except Exception as exc:  # hata yutulmaz, listeye yazılır (görüntüleme için)
            self.llm_errors.append(f"çeviri başarısız: {exc}")
        # Önlem önerisi (sadece kaynak bilgilerinden)
        try:
            rem = self._llm.suggest_remediation(advisory)
            if rem:
                advisory.remediation_tr = rem
        except Exception as exc:
            self.llm_errors.append(f"önlem önerisi başarısız: {exc}")
        advisory.quality_status = QualityStatus.review  # LLM çıktısı her zaman incelemeye gider
        return advisory

    def generate_qa(self, advisory: SecurityAdvisory, model_used: str = "offline") -> Any | None:
        """Kaynakla desteklenen soru-cevap çifti üretir (LLM varsa)."""
        if self._llm is None:
            return None
        try:
            return self._llm.generate_qa(advisory, model_used)
        except Exception as exc:
            self.llm_errors.append(f"QA üretimi başarısız: {exc}")
            return None


def run_pipeline(
    db: Database,
    connectors: dict[str, Any],
    limit: int | None = None,
    resume: bool = False,
    full_history: bool = False,
    since: str | None = None,
) -> dict[str, PipelineResult]:
    """Birden fazla kaynağı sırayla çalıştırır; birinin hata vermesi diğerlerini durdurmaz."""
    pipeline = Pipeline(db)
    results: dict[str, PipelineResult] = {}
    for source_name, connector in connectors.items():
        try:
            results[source_name] = pipeline.run_source(
                source_name,
                connector,
                limit=limit,
                resume=resume,
                full_history=full_history,
                since=since,
            )
        except Exception as exc:  # pragma: no cover - toplam hatayı engelle
            results[source_name] = PipelineResult(source=source_name)
            results[source_name].status = SourceRunStatus.failed
            results[source_name].errors += 1
            results[source_name].error_messages.append(str(exc))
    return results


def _llm_calls_in_parallel(
    llm: Any, advisory: SecurityAdvisory, model_label: str
) -> tuple[Any, Any, Any, list[str]]:
    """Çeviri/önlem/QA çağrılarını EŞZAMANLI çalıştırır.

    Her kayıt 3 ayrı LLM çağrısı yapar (çeviri, önlem, QA). Bunlar birbirine
    bağımlı olmadığından paralel çalıştırılarak kayıt süresi ~3 kat kısalır.
    Dönen: (çeviri, önlem, qa, hatalar). Hatalar sessizce yutulmaz.
    """
    errors: list[str] = []
    text = advisory.description_original or advisory.title or ""

    def _call(fn, err_label):
        try:
            return fn()
        except Exception as exc:
            errors.append(f"{err_label} başarısız: {exc}")
            return None

    with ThreadPoolExecutor(max_workers=3) as ex:
        f_tr = ex.submit(_call, lambda: llm.translate_to_tr(text), "çeviri")
        f_rem = ex.submit(_call, lambda: llm.suggest_remediation(advisory), "önlem önerisi")
        f_qa = ex.submit(_call, lambda: llm.generate_qa(advisory, model_label), "QA üretimi")
        tr = f_tr.result()
        rem = f_rem.result()
        qa = f_qa.result()
    return tr, rem, qa, errors


def format_progress_line(info: dict[str, Any]) -> str:
    """İlerleme bilgisinden insan-okur tek satır üretir (CLI ve panel paylaşır)."""
    flags = []
    if info["translated"]:
        flags.append("✓çeviri(yeni)")
    elif info.get("had_translation_before"):
        flags.append("=çeviri(zaten var)")
    else:
        flags.append("—çeviri(üretilemedi)")
    flags.append("✓önlem" if info["remediation"] else "—önlem")
    flags.append("✓QA" if info["qa_created"] else "—QA")
    line = (
        f"[{info['index']}/{info['total']}] {info['source_id']} "
        f"{' | '.join(flags)} ({info['elapsed_s']}s)"
    )
    if info.get("translation_snippet"):
        line += f' — "{info["translation_snippet"]}..."'
    if info.get("qa_note"):
        line += f" · QA: {info['qa_note']}"
    if info.get("errors"):
        line += " · HATA: " + "; ".join(info["errors"])
    return line


def run_enrichment(
    db: Database,
    llm: Any,
    *,
    provider_name: str,
    limit: int = 50,
    quality_status: str = "review",
    on_progress: Any = None,
    workers: int = 3,
) -> dict[str, int]:
    """İnceleme kuyruğundaki kayıtları LLM ile zenginleştirir.

    CLI ``enrich`` komutu ile Streamlit paneli AYNI fonksiyonu kullanır
    (panel CLI'yi taklit etmez, paylaşılan iş mantığını çağırır).

    Args:
        on_progress: İsteğe bağlı geri çağrısı; her kayıt için ``dict``
            (index, total, record_id, source_id, translated,
            had_translation_before, remediation, qa_created, qa_note, errors,
            elapsed_s, translation_snippet) alır. CLI ``--verbose`` ve panel
            ilerleme çubuğu bunu kullanır.
        workers: Kayıt başına eşzamanlı LLM çağrısı. Her kayıt 3 bağımsız
            çağrı yapar (çeviri/önlem/QA); ``workers=3`` ile bunlar paralel
            çalışır ve kayıt süresi ~3 kat kısalır. ``workers=1`` seridir.

    Returns:
        ``{"processed": n, "enriched": n, "qa_count": n}``
    """
    pipeline = Pipeline(db)
    pipeline.attach_llm(llm)
    advisories = db.list_advisories(quality_status=quality_status, limit=limit)
    model_label = f"{provider_name}:{llm.model or '-'}"
    parallel = workers > 1
    enriched = 0
    qa_count = 0
    total = len(advisories)
    for idx, adv in enumerate(advisories, start=1):
        started = time.perf_counter()
        pipeline.llm_errors.clear()
        before_tr = adv.description_tr
        if parallel:
            # 3 çağrı eşzamanlı; sonuçlar tek tek uygulanır (DB yazımları seri)
            tr, rem, qa, errs = _llm_calls_in_parallel(llm, adv, model_label)
            if tr:
                adv.description_tr = tr
            if rem:
                adv.remediation_tr = rem
            adv.quality_status = QualityStatus.review
            pipeline.llm_errors.extend(errs)
        else:
            pipeline.enrich_with_llm(adv)
        # Üretilen Türkçe metinleri kalıcı hale getir
        db.update_advisory_enrichment(
            adv.record_id,
            description_tr=adv.description_tr,
            remediation_tr=adv.remediation_tr,
            quality_status=adv.quality_status,
            quality_issues=adv.quality_issues,
        )
        # Kaynakla desteklenen soru-cevap örneğini üret ve sakla
        if not parallel:
            qa = pipeline.generate_qa(adv, model_used=model_label)
        qa_saved = qa is not None and db.insert_qa_pair(qa)
        if qa_saved:
            qa_count += 1
        if adv.description_tr != before_tr or adv.remediation_tr:
            enriched += 1

        if on_progress is not None:
            translated = bool(adv.description_tr) and adv.description_tr != before_tr
            had_translation_before = bool(before_tr)
            if qa_saved:
                qa_note = "kaynakla desteklendi, incelemede"
            elif qa is None and pipeline.llm_errors:
                qa_note = "hata — yukarıdaki HATA satırına bakın"
            elif qa is None:
                qa_note = "model kaynakla desteklenmedi olarak işaretledi"
            else:
                qa_note = "daha önce üretilmiş — tekrar eklenmedi (aynı QA iki kez girmez)"
            snippet = (adv.description_tr or "")[:80]
            on_progress(
                {
                    "index": idx,
                    "total": total,
                    "record_id": adv.record_id,
                    "source_id": adv.source_id,
                    "translated": translated,
                    "had_translation_before": had_translation_before,
                    "remediation": bool(adv.remediation_tr),
                    "qa_created": qa_saved,
                    "qa_note": qa_note,
                    "errors": list(pipeline.llm_errors),
                    "elapsed_s": round(time.perf_counter() - started, 1),
                    "translation_snippet": snippet,
                }
            )
    return {"processed": total, "enriched": enriched, "qa_count": qa_count}
