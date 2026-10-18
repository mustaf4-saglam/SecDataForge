"""SecDataForge Streamlit yönetim paneli.

Çalıştırma: streamlit run app/dashboard.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

# Paket kaynak kodunun (kurulmadan da) import edilebilmesi için src dizinini ekle
_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from secdataforge.config import settings
from secdataforge.database import Database
from secdataforge.exporters import export_csv, export_jsonl, export_qa_csv, export_qa_jsonl
from secdataforge.llm.factory import (
    PROVIDER_NAMES,
    ProviderConfigError,
    create_provider,
    describe_provider,
    provider_needs_terms,
)
from secdataforge.pipeline import format_progress_line, run_enrichment, run_pipeline
from secdataforge.quality import generate_quality_report
from secdataforge.sources.github_advisories import GitHubAdvisoriesConnector
from secdataforge.sources.osv import OSVConnector

st.set_page_config(page_title="SecDataForge", page_icon="🛡️", layout="wide")

st.title("🛡️ SecDataForge — Siber Güvenlik Veri Seti Yönetim Paneli")
st.caption("Açık kaynak siber güvenlik veri seti üretim aracı. LLM entegrasyonu opsiyoneldir.")


@st.cache_resource
def get_db():
    return Database(settings.db_path)


def source_status(db):
    st.subheader("Kaynaklar ve Bağlantı Durumu")
    cols = st.columns(2)
    for i, name in enumerate(("github", "osv")):
        with cols[i % 2]:
            run = db.get_latest_source_run(name)
            count = db.count_advisories(source=name)
            st.metric(label=name.upper(), value=count, delta=None)
            if run is None:
                st.info("Henüz çalıştırılmadı.")
            else:
                st.write(f"Son işlem: {run.status.value}")
                st.write(
                    f"Çekilen: {run.records_fetched}, Eklenen: {run.records_inserted}, "
                    f"Tekrarlı: {run.duplicates}, Hata: {run.errors}"
                )
                if run.error_message:
                    st.error(run.error_message[:300])


def collect_ui(db):
    st.subheader("Toplama İşlemi")
    source = st.selectbox("Kaynak", ["all", "github", "osv"], index=0)
    limit = st.number_input(
        "Kaynak başına kayıt limiti", min_value=1, max_value=10000, value=500, step=50
    )

    col1, col2, col3 = st.columns(3)
    with col1:
        resume = st.checkbox(
            "--resume (son imleçten devam et)",
            value=True,
            help="Varsayılan: son imleçten devam eder, sadece yenileri alır",
        )
    with col2:
        full_history = st.checkbox(
            "--full-history (baştan çek)",
            value=False,
            help="İmleci yok say, en yeniden başlayarak geriye doğru tüm geçmişi çeker. --resume ile çelişir; bu seçeneğe basılırsa --resume yoksayılır.",
        )
    with col3:
        since = st.text_input(
            "--since (YYYY-MM-DD)",
            value="",
            placeholder="2024-01-01",
            help="Bu tarihten eski kayıtlar atlanır (client-side filtre). Boş = filtre yok.",
        )

    result_placeholder = st.empty()
    if st.button("Toplamayı Başlat", type="primary"):
        # Seçenekler mantığı
        use_resume = resume and not full_history
        since_val = since.strip() if since.strip() else None

        # Önceki hata/sonuç alanını temizle
        result_placeholder.empty()
        with st.spinner("Yeni toplama başlatılıyor..."):
            all_connectors = {"github": GitHubAdvisoriesConnector(), "osv": OSVConnector()}
            connectors = all_connectors if source == "all" else {source: all_connectors[source]}
            try:
                results = run_pipeline(
                    db,
                    connectors,
                    limit=int(limit),
                    resume=use_resume,
                    full_history=full_history,
                    since=since_val,
                )
            except Exception as exc:
                result_placeholder.error(f"Toplama hatası: {exc}")
                results = {}
            finally:
                for connector in all_connectors.values():
                    connector.close()
        st.session_state["last_results"] = results
        with result_placeholder.container():
            st.success("Toplama tamamlandı.")
            if results:
                for name, res in results.items():
                    st.write(
                        f"**{name}**: durum={res.status.value}, çekilen={res.fetched}, eklenen={res.inserted}, tekrarlı={res.duplicates}, hata={res.errors}"
                    )
                    for msg in res.error_messages:
                        st.warning(f"{name}: {msg}")


def quality_ui(db):
    st.subheader("Veri Kalitesi Raporu")
    report = generate_quality_report(db)
    cols = st.columns(4)
    metrics = [
        ("Toplam eklenen", report.total_inserted),
        (
            "Geçerli (valid)",
            report.by_source and sum(v.get("valid", 0) for v in report.by_source.values()) or 0,
        ),
        (
            "İncelemede (review)",
            report.by_source and sum(v.get("review", 0) for v in report.by_source.values()) or 0,
        ),
        ("Bilinmeyen lisans", report.unknown_license_count),
    ]
    for col, (label, value) in zip(cols, metrics):
        col.metric(label, value)

    st.write("Eksik alan oranı:", f"{report.missing_field_ratio:.2%}")
    st.write("Türkçeleştirilen kayıt:", report.translated_count)
    st.write("İnceleme bekleyen AI çıktısı:", report.pending_ai_review)
    st.write("Onaylanmış soru-cevap:", report.approved_qa_count)
    st.write("Kaynak kaydı bulunmayan QA:", report.orphan_qa_count)

    if report.by_source:
        st.bar_chart({src: counts.get("inserted", 0) for src, counts in report.by_source.items()})


def dataset_ui(db):
    st.subheader("Veri Kümesi ve Filtreleme")
    source_filter = st.selectbox("Kaynak filtresi", ["tümü", "github", "osv"], index=0)
    quality_filter = st.selectbox(
        "Kalite durumu", ["valid", "review", "rejected", "pending", "tümü"], index=0
    )
    limit = st.number_input("Görüntüleme sınırı", min_value=1, max_value=1000, value=50, step=10)

    source = None if source_filter == "tümü" else source_filter
    quality = None if quality_filter == "tümü" else quality_filter

    advisories = db.list_advisories(source=source, quality_status=quality, limit=int(limit))
    st.write(f"Gösterilen kayıt: {len(advisories)}")
    if advisories:
        rows = []
        for adv in advisories:
            rows.append(
                {
                    "record_id": adv.record_id,
                    "source": adv.source,
                    "source_id": adv.source_id,
                    "title": adv.title or "",
                    "severity": adv.severity or "",
                    "quality_status": adv.quality_status.value
                    if isinstance(adv.quality_status, str)
                    else str(adv.quality_status),
                    "cve_ids": ", ".join(adv.cve_ids or []),
                    "published_at": adv.published_at.isoformat() if adv.published_at else "",
                }
            )
        st.dataframe(rows, width="stretch", hide_index=True)


def ai_review_ui(db):
    st.subheader("İnceleme Bekleyen AI Kayıtları")
    pending = db.list_qa_pairs(validation_status="pending", limit=50)
    st.write(f"Bekleyen QA sayısı: {len(pending)}")
    if pending:
        rows = [
            {
                "qa_id": qa.qa_id,
                "question": qa.question,
                "answer": qa.answer,
                "model": qa.model_used,
                "insan_inceleme": "Evet" if qa.needs_human_review else "Hayır",
            }
            for qa in pending
        ]
        st.dataframe(rows, width="stretch", hide_index=True)


def export_ui(db):
    st.subheader("Çıktı İndirme (JSONL / CSV)")
    quality_choice = st.selectbox("Dışa aktarılacak kalite", ["valid", "tümü"], index=0)
    quality = None if quality_choice == "tümü" else "valid"

    prefix = st.text_input(
        "Dosya adı öneki (--prefix)",
        value="secdataforge",
        placeholder="secdataforge_2024_01_01_2024_12_31",
        help="Tarih aralığı için ayrı dosya: secdataforge_2024_01_01_2024_12_31. Boş bırakılırsa 'secdataforge' kullanılır.",
    )
    prefix = prefix.strip() or "secdataforge"

    col1, col2 = st.columns(2)
    with col1:
        if st.button("JSONL hazırla"):
            path = Path(settings.exports_dir) / f"{prefix}.jsonl"
            n = export_jsonl(db, path, quality_status=quality)
            st.session_state["jsonl_path"] = str(path)
            st.session_state["jsonl_count"] = n
            st.success(f"{n} kayıt hazırlandı: {path.name}")
    with col2:
        if st.button("CSV hazırla"):
            path = Path(settings.exports_dir) / f"{prefix}.csv"
            n = export_csv(db, path, quality_status=quality)
            st.session_state["csv_path"] = str(path)
            st.session_state["csv_count"] = n
            st.success(f"{n} kayıt hazırlandı: {path.name}")

    if st.session_state.get("jsonl_path") and Path(st.session_state["jsonl_path"]).exists():
        st.download_button(
            "JSONL indir",
            data=Path(st.session_state["jsonl_path"]).read_bytes(),
            file_name=Path(st.session_state["jsonl_path"]).name,
            mime="application/jsonl",
        )
    if st.session_state.get("csv_path") and Path(st.session_state["csv_path"]).exists():
        st.download_button(
            "CSV indir",
            data=Path(st.session_state["csv_path"]).read_bytes(),
            file_name=Path(st.session_state["csv_path"]).name,
            mime="text/csv",
        )

    # --- AI soru-cevap (QA) dışa aktarımı: indirilebilir, eğitimde kullanılabilir ---
    st.markdown("#### AI Soru-Cevap (QA) Çiftleri")
    qa_status_choice = st.selectbox(
        "QA filtresi", ["tümü", "pending", "approved", "rejected"], index=0
    )
    qa_filter = None if qa_status_choice == "tümü" else qa_status_choice
    st.caption(
        "Alanlar: soru, cevap, dayanak alanları, kullanılan model, doğrulama durumu "
        "ve kaynak bağlamı (lisans dahil). Çoklu alanlar `|` ile ayrılır."
    )

    qa1, qa2 = st.columns(2)
    with qa1:
        if st.button("QA JSONL hazırla"):
            path = Path(settings.exports_dir) / "secdataforge_qa.jsonl"
            n = export_qa_jsonl(db, path, validation_status=qa_filter)
            st.session_state["qa_jsonl_path"] = str(path)
            st.session_state["qa_jsonl_count"] = n
            st.success(f"{n} soru-cevap hazırlandı.")
    with qa2:
        if st.button("QA CSV hazırla"):
            path = Path(settings.exports_dir) / "secdataforge_qa.csv"
            n = export_qa_csv(db, path, validation_status=qa_filter)
            st.session_state["qa_csv_path"] = str(path)
            st.session_state["qa_csv_count"] = n
            st.success(f"{n} soru-cevap hazırlandı.")

    if st.session_state.get("qa_jsonl_path") and Path(st.session_state["qa_jsonl_path"]).exists():
        st.download_button(
            "QA JSONL indir",
            data=Path(st.session_state["qa_jsonl_path"]).read_bytes(),
            file_name="secdataforge_qa.jsonl",
            mime="application/jsonl",
            key="qa_jsonl_dl",
        )
    if st.session_state.get("qa_csv_path") and Path(st.session_state["qa_csv_path"]).exists():
        st.download_button(
            "QA CSV indir",
            data=Path(st.session_state["qa_csv_path"]).read_bytes(),
            file_name="secdataforge_qa.csv",
            mime="text/csv",
            key="qa_csv_dl",
        )


def llm_ui(db):
    """LLM sağlayıcı seçimi, model listesi, bağlantı testi ve zenginleştirme.

    Güvenlik: API anahtarları yalnızca sunucu tarafında (.env/config) okunur;
    tarayıcıya/panel çıktısına ASLA gönderilmez (yalnızca "tanımlı/tanımsız").
    """
    from secdataforge.llm.evren import (
        EvrenAPIError,
        accept_terms,
        require_terms,
        terms_accepted,
    )

    st.subheader("LLM Sağlayıcı ve EVREN Ayarları")
    st.caption(
        "Zenginleştirme panelde de CLI ile AYNI iş mantığını kullanır "
        "(`secdataforge enrich`). Anahtarlar sunucu tarafında kalır."
    )

    provider_name = st.selectbox("Sağlayıcı", list(PROVIDER_NAMES), index=0)
    needs_terms = provider_needs_terms(provider_name)

    # --- EVREN kullanım şartı onayı (otomatik ONAY YOK) ---
    if needs_terms:
        accepted = terms_accepted()
        with st.expander("Kullanım Şartları", expanded=not accepted):
            st.write(f"**Hizmet:** `{settings.evren_base_url}`")
            st.write(f"**Şart adresi:** {settings.evren_terms_url}")
            st.caption(
                "Şartları bu adres üzerinden okumak sizin sorumluluğunuzdadır; "
                "bu panel şartları otomatik kabul etmez."
            )
            if accepted:
                st.success(
                    f"Onaylı (tarih: {accepted.get('accepted_at', '?')}) — "
                    f"kayıt: `{accepted.get('terms_url', '?')}`"
                )
            else:
                confirmed = st.checkbox(
                    "EVREN kullanım şartlarını okudum ve kabul ediyorum", value=False
                )
                if st.button("Onayı Kaydet", disabled=not confirmed):
                    accept_terms(
                        terms_url=settings.evren_terms_url,
                        base_url=settings.evren_base_url,
                        api_key=settings.evren_api_key,
                    )
                    st.success("Kullanım şartları onayı kaydedildi.")
                    st.rerun()

    # --- Model seçimi (EVREN'de /models listesinden, tahmini model adı YOK) ---
    default_model = {
        "ollama": settings.llm_model,
        "openai_compatible": settings.llm_model,
        "gemini": "gemini-1.5-flash",
        "claude": "claude-3-5-sonnet-20241022",
        "huggingface": "meta-llama/Llama-3.1-8B-Instruct",
        "evren": settings.evren_model or "",
    }.get(provider_name, "")

    model = default_model
    if provider_name == "evren":
        col_a, col_b = st.columns([1, 3])
        with col_a:
            if st.button("Modelleri Getir (/models)"):
                try:
                    inst = create_provider(provider_name, require_api_key=False)
                    st.session_state["evren_models"] = inst.list_models()
                    inst.close()
                except (ProviderConfigError, EvrenAPIError) as exc:
                    st.error(str(getattr(exc, "message", None) or exc))
        with col_b:
            models = st.session_state.get("evren_models") or []
            if models:
                model = st.selectbox("EVREN model kimliği", models, index=0)
            else:
                model = st.text_input(
                    "EVREN model kimliği (önce 'Modelleri Getir' ile listeleyin)",
                    value=default_model,
                )
    else:
        model = st.text_input("Model", value=default_model)

    # --- Güvenli tanım: anahtarın kendisi asla gösterilmez ---
    try:
        probe = create_provider(provider_name, model=model, require_api_key=False)
        info = describe_provider(provider_name, probe)
        probe.close()
        st.caption(
            f"base_url: `{info['base_url']}` · "
            f"API anahtarı: "
            f"{'✅ tanımlı' if info['api_key_configured'] else '❌ tanımlı değil'}"
        )
    except ProviderConfigError as exc:
        st.error(str(exc))
        return

    # --- Bağlantı testi ---
    if st.button("Bağlantıyı Test Et"):
        try:
            inst = create_provider(provider_name, model=model)
        except ProviderConfigError as exc:
            st.error(str(exc))
            return
        with st.spinner("Test ediliyor..."):
            try:
                if provider_name == "evren":
                    result = inst.test_connection(do_chat=True)
                    if result["reachable"]:
                        st.write("✅ API erişimi var")
                    if result["auth_ok"]:
                        st.write(f"✅ Kimlik geçerli — {len(result['models'])} model listelendi")
                        if result["models"]:
                            st.code("\n".join(result["models"]), language=None)
                    if result["chat_ok"]:
                        st.write(f"✅ Kısa sohbet başarılı (model: {result['model_used']})")
                    for err in result["errors"]:
                        st.error(err)
                    if not (result["auth_ok"] and (result["chat_ok"])):
                        st.warning("Bağlantı testi eksik adımlarla tamamlandı.")
                else:
                    if inst.is_available():
                        st.success(f"Sağlayıcı erişilebilir (model: {inst.model})")
                    else:
                        st.error(
                            "Sağlayıcı erişilebilir değil; anahtar/base_url/model ayarlarını kontrol edin."
                        )
            finally:
                inst.close()

    # --- İnceleme kuyruğunu zenginleştirme (CLI ile paylaşılan fonksiyon) ---
    st.markdown("#### İnceleme Kuyruğunu Zenginleştir")
    limit = st.number_input(
        "İşlenecek maksimum kayıt",
        min_value=1,
        max_value=500,
        value=10,
        step=5,
        key="llm_enrich_limit",
    )
    workers = st.number_input(
        "Kayıt başına eşzamanlı çağrı (1 = seri)",
        min_value=1,
        max_value=8,
        value=3,
        step=1,
        key="llm_enrich_workers",
        help="Çeviri, önlem ve QA çağrıları paralel çalışır; 3 ≈ 3 kat hızlı.",
    )
    if st.button("Zenginleştirmeyi Başlat", type="primary"):
        if needs_terms:
            try:
                require_terms()
            except EvrenAPIError as exc:
                st.error(exc.message)
                return
        try:
            inst = create_provider(provider_name, model=model)
        except ProviderConfigError as exc:
            st.error(str(exc))
            return
        if not inst.is_available():
            st.error("Sağlayıcı erişilebilir değil; bağlantı testini çalıştırın.")
            inst.close()
            return
        try:
            # Canlı ilerleme: her kayıtta çubuk + son satırlar güncellenir
            progress_bar = st.progress(0.0, text="Başlıyor...")
            log_slot = st.empty()
            log_lines: list[str] = []

            def _on_progress(info: dict) -> None:
                log_lines.append(format_progress_line(info))
                progress_bar.progress(
                    info["index"] / max(info["total"], 1),
                    text=f"{info['index']}/{info['total']} işlendi",
                )
                # Son 10 satır canlı gösterilir (uzun çalışmalarda kaybolmaz)
                with log_slot.container():
                    prefix = "⚠ " if info.get("errors") else ""
                    st.code(prefix + "\n".join(log_lines[-10:]), language=None)

            with st.spinner("LLM zenginleştirmesi çalışıyor (yerel modelde uzun sürebilir)..."):
                stats = run_enrichment(
                    db,
                    inst,
                    provider_name=provider_name,
                    limit=int(limit),
                    quality_status="review",
                    on_progress=_on_progress,
                    workers=int(workers),
                )
            progress_bar.progress(1.0, text="Tamamlandı")
            st.success(
                f"İşlenen: {stats['processed']} · Zenginleştirilen: {stats['enriched']} · "
                f"QA: {stats['qa_count']} (tümü inceleme kuyruğunda)"
            )
            with st.expander(f"İlerleme günlüğü ({len(log_lines)} satır)", expanded=False):
                st.code("\n".join(log_lines) if log_lines else "(kayıt yok)", language=None)
            if stats["processed"] and stats["enriched"] == 0 and stats["qa_count"] == 0:
                st.warning(
                    "Kayıtlar işlendi ama çıktı üretilemedi; model adını ve modelin "
                    "geçerli JSON ürettiğini kontrol edin."
                )
        except Exception as exc:  # panel çökmesin
            st.error(f"Zenginleştirme hatası: {exc}")
        finally:
            inst.close()


def main():
    db = get_db()

    tab_sources, tab_collect, tab_quality, tab_dataset, tab_ai, tab_llm, tab_export = st.tabs(
        [
            "Kaynaklar",
            "Toplama",
            "Kalite",
            "Veri Kümesi",
            "AI İnceleme",
            "LLM / EVREN",
            "Dışa Aktarım",
        ]
    )

    with tab_sources:
        source_status(db)
    with tab_collect:
        collect_ui(db)
    with tab_quality:
        quality_ui(db)
    with tab_dataset:
        dataset_ui(db)
    with tab_ai:
        ai_review_ui(db)
    with tab_llm:
        llm_ui(db)
    with tab_export:
        export_ui(db)

    st.sidebar.markdown("### Yapılandırma")
    st.sidebar.write(f"Veritabanı: `{settings.db_path}`")
    st.sidebar.write(f"LLM etkin: `{settings.llm_enabled}`")
    st.sidebar.write(f"Varsayılan limit: `{settings.default_record_limit}`")
    # Not: db bağlantısı st.cache_resource ile paylaşılır ve burada KAPATILMAZ;
    # kapatılırsa Streamlit her yeniden çalıştırmada kapalı bağlantıya erişir.


if __name__ == "__main__":
    main()
