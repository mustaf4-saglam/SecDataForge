"""Komut satırı arayüzü (Typer).

Komutlar:
- sources: yapılandırılan kaynakları ve durumlarını listeler
- collect: veri toplama hattını çalıştırır
- validate: mevcut kayıtların kalitesini yeniden değerlendirir ve rapor verir
- enrich: LLM ile isteğe bağlı zenginleştirme uygular
- export: kayıtları JSONL/CSV olarak dışa aktarır
- report: veri kalitesi raporu gösterir
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .config import settings
from .database import Database
from .exporters import export_csv, export_jsonl, export_qa_csv, export_qa_jsonl
from .pipeline import Pipeline, format_progress_line, run_enrichment, run_pipeline
from .quality import generate_quality_report
from .sources.github_advisories import GitHubAdvisoriesConnector
from .sources.osv import OSVConnector

app = typer.Typer(
    name="secdataforge",
    help="SecDataForge: açık kaynak siber güvenlik veri seti üretim aracı.",
    rich_markup_mode="rich",
)
console = Console()


def _db() -> Database:
    return Database(settings.db_path)


def _connectors() -> dict[str, object]:
    """Yapılandırılan (etkin) bağlayıcıları döndürür."""
    connectors: dict[str, object] = {}
    github = GitHubAdvisoriesConnector()
    osv = OSVConnector()
    connectors["github"] = github
    connectors["osv"] = osv
    return connectors


@app.command()
def sources() -> None:
    """Yapılandırılan veri kaynaklarını ve son durumlarını gösterir."""
    db = _db()
    table = Table(title="SecDataForge Veri Kaynakları")
    table.add_column("Kaynak", style="cyan")
    table.add_column("Durum", style="green")
    table.add_column("Kayıt", justify="right")
    table.add_column("Son İşlem", style="magenta")
    table.add_column("Hata", justify="right")

    for name in ("github", "osv"):
        run = db.get_latest_source_run(name)
        count = db.count_advisories(source=name)
        if run is None:
            durum = "hiç çalıştırılmadı"
            son_islem = "-"
            hata = "0"
        else:
            durum = run.status.value
            son_islem = run.started_at.strftime("%Y-%m-%d %H:%M") if run.started_at else "-"
            hata = str(run.errors)
        table.add_row(name, durum, str(count), son_islem, hata)

    console.print(table)
    db.close()


@app.command()
def collect(
    source: str = typer.Argument("all", help="Kaynak adı: github, osv veya 'all'."),
    limit: int = typer.Option(None, "--limit", "-l", help="Kaynak başına maksimum kayıt sayısı."),
    resume: bool = typer.Option(
        False, "--resume", help="Son imleçten devam et (varsayılan davranış)."
    ),
    full_history: bool = typer.Option(
        False, "--full-history", help="İmleci yok say, baştan başla (tüm geçmişi çek)."
    ),
    since: str = typer.Option(
        None, "--since", help="Bu tarihten (YYYY-MM-DD) sonrası kayıtları al (client-side filtre)."
    ),
) -> None:
    """Veri toplama hattını çalıştırır. Bir kaynak hata verirse diğerleri durmaz.

    Varsayılan: --resume ile son imleçten devam eder (sadece yenileri).
    --full-history: İmleci yok say, en yeniden başlayarak geriye doğru tüm geçmişi çeker.
    --since: YYYY-MM-DD formatında tarih; bu tarihten eski kayıtlar atlanır (client-side).
    """
    limit = limit or settings.default_record_limit
    all_connectors = _connectors()

    if source == "all":
        chosen = all_connectors
    elif source in all_connectors:
        chosen = {source: all_connectors[source]}
    else:
        console.print(f"[red]Bilinmeyen kaynak: {source}[/red] (seçenekler: github, osv, all)")
        raise typer.Exit(code=1)

    # full_history ve resume çelişir; full_history öncelikli
    use_resume = resume and not full_history

    db = _db()
    try:
        results = run_pipeline(
            db, chosen, limit=limit, resume=use_resume, full_history=full_history, since=since
        )
    finally:
        db.close()
        for connector in all_connectors.values():
            connector.close()

    table = Table(title="Toplama Sonuçları")
    table.add_column("Kaynak", style="cyan")
    table.add_column("Durum", style="green")
    table.add_column("Çekilen", justify="right")
    table.add_column("Eklenen", justify="right")
    table.add_column("Tekrarlı", justify="right")
    table.add_column("Hata", justify="right")

    for name, res in results.items():
        table.add_row(
            name,
            res.status.value,
            str(res.fetched),
            str(res.inserted),
            str(res.duplicates),
            str(res.errors),
        )
        for msg in res.error_messages:
            console.print(f"  [yellow]![/yellow] {name}: {msg}")

    console.print(table)


@app.command()
def validate() -> None:
    """Mevcut kayıtların kalitesini yeniden değerlendirir ve rapor verir.

    Kaynak bağlayıcılarında tanımlı güncel lisans politikası (ör. GitHub
    Advisory Database CC-BY-4.0) mevcut kayıtlara da uygulanır; böylece
    lisans kararı sonradan verilen kayıtlar inceleme kuyruğundan çıkar.
    """
    db = _db()
    connectors = _connectors()
    try:
        advisories = db.list_advisories(limit=100000)
        updated = 0
        from .schemas import QualityStatus

        pipeline = Pipeline(db)
        for adv in advisories:
            connector = connectors.get(adv.source)
            if connector is not None and pipeline.apply_license_policy(adv, connector):
                db.update_advisory_license(adv.record_id, adv.license, adv.license_status)
            status, issues = pipeline._validate_advisory(adv)
            if (
                (
                    adv.quality_status.value
                    if isinstance(adv.quality_status, QualityStatus)
                    else str(adv.quality_status)
                )
                != status.value
            ) or (adv.quality_issues or []) != (issues or []):
                db.update_quality_status(adv.record_id, status, issues)
                updated += 1

        report = generate_quality_report(db)
        console.print(f"[green]Değerlendirme tamamlandı.[/green] {updated} kayıt güncellendi.")
        _print_report(report)
    finally:
        db.close()
        for connector in connectors.values():
            connector.close()


@app.command()
def enrich(
    llm: bool = typer.Option(
        settings.llm_enabled,
        "--llm",
        help="LLM zenginleştirmesini etkinleştir (sağlayıcı yapılandırılmış olmalı).",
    ),
    provider: str = typer.Option(
        "ollama",
        "--provider",
        help="LLM sağlayıcısı: ollama, openai_compatible, gemini, claude, huggingface veya evren.",
    ),
    model: str = typer.Option(None, "--model", help="Kullanılacak model adı."),
    limit: int = typer.Option(50, "--limit", "-l", help="İşlenecek maksimum kayıt sayısı."),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Her kayıt için adım adım ilerleme ve hata ayrıntısı göster.",
    ),
    workers: int = typer.Option(
        3,
        "--workers",
        "-w",
        min=1,
        max=8,
        help="Kayıt başına eşzamanlı LLM çağrısı (çeviri/önlem/QA paralel çalışır; "
        "1 = seri, varsayılan 3 ≈ 3 kat hızlı).",
    ),
) -> None:
    """İsteğe bağlı LLM zenginleştirmesi (Türkçe çeviri, önlem, QA üretimi).

    LLM varsayılan olarak kapalıdır; --llm ile (veya .env içinde LLM_ENABLED=true)
    etkinleştirilir. Çıktılar inceleme kuyruğunda tutulur.

    Sağlayıcılar:
      - ollama: Yerel Ollama sunucusu (varsayılan: localhost:11434)
      - openai_compatible: OpenAI ve uyumlu API'ler (LLM_API_KEY gerekli)
      - gemini: Google Gemini (GEMINI_API_KEY gerekli)
      - claude: Anthropic Claude (CLAUDE_API_KEY gerekli)
      - huggingface: Açık kaynak modeller (HUGGINGFACE_API_KEY gerekli)
      - evren: EVREN LLM API (EVREN_API_KEY gerekli, kullanım şartı onayı ister)
    """
    if not llm:
        console.print(
            "[yellow]LLM devre dışı.[/yellow] --llm bayrağıyla etkinleştirebilirsiniz. "
            "API anahtarını kod içinde saklamayın (.env dosyasını kullanın)."
        )
        raise typer.Exit(code=0)

    from .llm.evren import EvrenAPIError, require_terms
    from .llm.factory import ProviderConfigError, create_provider

    # EVREN: açık kullanıcı onayı olmadan çalışmaz (şartlar otomatik kabul edilmez).
    if provider.strip().lower() == "evren":
        try:
            require_terms()
        except EvrenAPIError as exc:
            console.print(f"[red]{exc.message}[/red]")
            raise typer.Exit(code=1) from exc

    try:
        provider_inst = create_provider(provider, model=model)
    except ProviderConfigError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    if not provider_inst.is_available():
        console.print(
            f"[red]LLM sağlayıcısı ({provider}, model: {provider_inst.model}) "
            f"şu anda erişilebilir değil.[/red] Model/API anahtarı/base_url "
            "ayarlarını kontrol edin."
        )
        raise typer.Exit(code=1)

    db = _db()
    try:
        if verbose:
            console.print(
                f"[dim]Sağlayıcı: {provider} · model: {provider_inst.model} · "
                f"base_url: {provider_inst.base_url} · sınır: {limit} kayıt · "
                f"eşzamanlı: {workers}[/dim]"
            )

        def _on_progress(info: dict) -> None:
            # Satır model metni içerebilir ([] karakterleri) — markup YOK.
            style = "red" if info["errors"] else "green"
            console.print(format_progress_line(info), style=style, markup=False)

        stats = run_enrichment(
            db,
            provider_inst,
            provider_name=provider,
            limit=limit,
            quality_status="review",
            on_progress=_on_progress if verbose else None,
            workers=workers,
        )
        console.print(
            f"[green]{stats['enriched']} kayıt LLM ile zenginleştirildi, "
            f"{stats['qa_count']} soru-cevap örneği üretildi (tümü inceleme kuyruğunda).[/green]"
        )
        if stats["processed"] and stats["enriched"] == 0 and stats["qa_count"] == 0:
            console.print(
                "[yellow]Uyarı: kayıtlar işlendi ancak hiçbir çıktı üretilemedi.[/yellow] "
                f"Model adını (şu an: {provider_inst.model}) ve modelin geçerli JSON "
                "ürettiğini kontrol edin."
            )
    finally:
        db.close()
        provider_inst.close()


@app.command()
def evren_setup(
    yes: bool = typer.Option(
        False,
        "--yes",
        help="Şartları okuyup kabul ettiğinizi komut satırından açıkça beyan eder "
        "(etkileşimli soru gösterilmez). Bu bayrağı vermek de bir açık onaydır.",
    ),
) -> None:
    """EVREN kullanım şartlarını gösterir ve açık onayınızı alır.

    EVREN'e zenginleştirme (enrich --provider evren) göndermeden önce bu komutu
    bir kez çalıştırmanız gerekir. Şartlar ASLA otomatik kabul edilmez; onay
    yalnızca sizin açık ifadenizle (interaktif soru veya --yes) kaydedilir.
    """
    from .llm.evren import TERMS_FILE, accept_terms, terms_accepted

    current = terms_accepted()
    if current:
        console.print("[green]EVREN kullanım şartları daha önce onaylanmış.[/green]")
        console.print(f"  Onay zamanı : {current.get('accepted_at', '?')}")
        console.print(f"  Şart adresi  : {current.get('terms_url', '?')}")
        console.print(f"  Kayıt dosyası: {TERMS_FILE}")
        console.print(
            "[yellow]Yeniden onaylamak için dosyayı silip komutu tekrar çalıştırın:[/yellow] "
            f"rm {TERMS_FILE}"
        )
        return

    terms_url = settings.evren_terms_url
    console.print("[bold]EVREN LLM API — Kullanım Şartları Onayı[/bold]")
    console.print(f"  Hizmet      : {settings.evren_base_url}")
    console.print(f"  Şart adresi : {terms_url}")
    console.print(
        "\nAşağıdaki bağlantıdan kullanım şartlarını OKUMANIZ gerekir. Bu araç "
        "şart metnini otomatik kabul etmez; yalnızca sizin açık onayınızı kaydeder.\n"
        "[dim]Not: Resmî şart adresi EVREN_TERMS_URL (.env) ile değiştirilebilir; "
        "adresi doğrulamak sizin sorumluluğunuzdadır.[/dim]\n"
    )
    console.print(f"  Kayıt dosyası: {TERMS_FILE} (API anahtarı İÇERMEZ)")

    if yes:
        accepted = True
        console.print(
            "\n[yellow]--yes bayrağı verildi:[/yellow] şartları okuyup kabul "
            "ettiğinizi komut satırından açıkça beyan ettiniz."
        )
    else:
        accepted = typer.confirm(
            "\nEVREN kullanım şartlarını okudum ve kabul ediyorum",
            default=False,
            show_default=True,
        )
    if not accepted:
        console.print("[red]Onay verilmedi; EVREN özellikleri kapalı kalacak.[/red]")
        raise typer.Exit(code=1)

    path = accept_terms(
        terms_url=terms_url,
        base_url=settings.evren_base_url,
        api_key=settings.evren_api_key,
    )
    console.print(f"[green]Kullanım şartları onayı kaydedildi:[/green] {path}")


@app.command()
def evren_test(
    model: str = typer.Option(
        None, "--model", help="Test edilecek model (boşsa /models listesinden)."
    ),
    no_chat: bool = typer.Option(False, "--no-chat", help="Sadece erişim+model listesini test et."),
) -> None:
    """EVREN API bağlantı testi: erişim → kimlik → model listesi → kısa sohbet.

    Her adım ayrı raporlanır; başarısız adımlar gizlenmez. API anahtarı
    hiçbir yere yazılmaz veya gösterilmez.
    """
    from .llm.evren import EvrenAPIError, EvrenProvider, terms_accepted

    if not settings.evren_api_key:
        console.print(
            "[red]EVREN_API_KEY ayarlanmamış.[/red] .env dosyasına ekleyin "
            "(.env.example'a bakın). Anahtarı asla koda yazmayın."
        )
        raise typer.Exit(code=1)

    accepted = terms_accepted()
    if accepted:
        console.print(
            f"[green]Kullanım şartları onaylı[/green] (tarih: {accepted.get('accepted_at', '?')})"
        )
    else:
        console.print(
            "[yellow]Kullanım şartları henüz onaylanmamış.[/yellow] "
            "Bağlantı testi çalıştırılabilir; zenginleştirme için önce "
            "`secdataforge evren-setup` çalıştırın."
        )

    try:
        provider = EvrenProvider(model=model)
    except EvrenAPIError as exc:  # pragma: no cover - yapılandırma hatası
        console.print(f"[red]{exc.message}[/red]")
        raise typer.Exit(code=1) from exc

    try:
        result = provider.test_connection(do_chat=not no_chat)
    finally:
        provider.close()

    console.print(f"\n[bold]Base URL:[/bold] {result['base_url']}")
    console.print("  [green]✓[/green] Erişim" if result["reachable"] else "  [red]✗[/red] Erişim")
    console.print(
        "  [green]✓[/green] Kimlik doğrulama (API anahtarı geçerli)"
        if result["auth_ok"]
        else "  [red]✗[/red] Kimlik doğrulama"
    )
    if result["auth_ok"]:
        models = result["models"]
        console.print(f"  [green]✓[/green] Model listesi: {len(models)} model")
        if models:
            table = Table(title="EVREN erişilebilir modeller")
            table.add_column("#", justify="right")
            table.add_column("Model kimliği")
            for i, mid in enumerate(models, start=1):
                table.add_row(str(i), mid)
            console.print(table)
            console.print(
                "[dim]Kullanmak için: EVREN_MODEL=.env'e yazın veya `--model` ile seçin.[/dim]"
            )
    if not no_chat:
        if result["chat_ok"]:
            console.print(
                f"  [green]✓[/green] Kısa sohbet testi başarılı (model: {result['model_used']})"
            )
        else:
            console.print("  [red]✗[/red] Kısa sohbet testi BAŞARISIZ")

    for err in result["errors"]:
        console.print(f"[red]Hata: {err}[/red]")

    if result["reachable"] and result["auth_ok"] and (no_chat or result["chat_ok"]):
        console.print("\n[green]EVREN bağlantı testi: TÜM ADIMLAR BAŞARILI[/green]")
        return
    console.print("\n[red]EVREN bağlantı testi: BAŞARISIZ adımlar var (yukarıya bakın).[/red]")
    raise typer.Exit(code=1)


@app.command()
def export(
    format: str = typer.Option(
        "both", "--format", "-f", help="Çıktı biçimi: jsonl, csv veya both."
    ),
    output: Path = typer.Option(settings.exports_dir, "--output", "-o", help="Çıktı dizini."),
    quality: str = typer.Option(
        "valid", "--quality", "-q", help="Dışa aktarılacak kalite durumu: valid veya all."
    ),
    source: str = typer.Option(None, "--source", "-s", help="Kaynak filtresi: github veya osv."),
    qa: bool = typer.Option(
        False,
        "--qa",
        help="AI soru-cevap çiftlerini de dışa aktar (secdataforge_qa.jsonl/.csv).",
    ),
    qa_status: str = typer.Option(
        "all",
        "--qa-status",
        help="QA filtresi: pending, approved, rejected veya all.",
    ),
    prefix: str = typer.Option(
        "secdataforge",
        "--prefix",
        help="Çıktı dosya adı öneki (ör. 'secdataforge_2024_01_01_2024_12_31' veya 'secdataforge_latest').",
    ),
) -> None:
    """Onaylanmış kayıtları JSONL ve/veya CSV olarak dışa aktarır.

    Varsayılan olarak sadece quality_status == valid kayıtları çıkarılır.
    ``--qa`` ile LLM'in ürettiği soru-cevap çiftleri ayrı dosyalara yazılır.
    ``--prefix`` ile dosya adını özelleştirin (tarih aralığı için: secdataforge_2024_01_01_2024_12_31).
    """
    if format not in ("jsonl", "csv", "both"):
        console.print(f"[red]Geçersiz format: {format}[/red] (jsonl, csv veya both)")
        raise typer.Exit(code=1)
    if quality not in ("valid", "all"):
        console.print(f"[red]Geçersiz kalite değeri: {quality}[/red] (valid veya all)")
        raise typer.Exit(code=1)
    if qa_status not in ("all", "pending", "approved", "rejected"):
        console.print(
            f"[red]Geçersiz --qa-status: {qa_status}[/red] (pending, approved, rejected veya all)"
        )
        raise typer.Exit(code=1)

    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    db = _db()
    try:
        qs = None if quality == "all" else quality
        count_jsonl = 0
        count_csv = 0
        base = prefix
        if format in ("jsonl", "both"):
            count_jsonl = export_jsonl(
                db, output / f"{base}.jsonl", source=source, quality_status=qs
            )
        if format in ("csv", "both"):
            count_csv = export_csv(db, output / f"{base}.csv", source=source, quality_status=qs)
        console.print(
            f"[green]Dışa aktarım tamamlandı.[/green] JSONL: {count_jsonl}, CSV: {count_csv} kayıt. Dosya: {base}.jsonl/.csv"
        )

        if qa:
            qa_filter = None if qa_status == "all" else qa_status
            qa_jsonl = 0
            qa_csv = 0
            if format in ("jsonl", "both"):
                qa_jsonl = export_qa_jsonl(
                    db, output / f"{base}_qa.jsonl", validation_status=qa_filter
                )
            if format in ("csv", "both"):
                qa_csv = export_qa_csv(db, output / f"{base}_qa.csv", validation_status=qa_filter)
            console.print(
                f"[green]QA dışa aktarım tamamlandı.[/green] "
                f"JSONL: {qa_jsonl}, CSV: {qa_csv} soru-cevap (filtre: {qa_status}). Dosya: {base}_qa.jsonl/.csv"
            )
            if qa_jsonl == 0 and qa_csv == 0:
                console.print(
                    "[yellow]QA dosyası boş: filtre veya üretilmiş QA yok "
                    "(`secdataforge enrich --llm ...` ile üretebilirsiniz).[/yellow]"
                )
    finally:
        db.close()


@app.command()
def report() -> None:
    """Veri kalitesi raporunu gösterir."""
    db = _db()
    try:
        report = generate_quality_report(db)
        _print_report(report)
    finally:
        db.close()


def _print_report(report) -> None:
    table = Table(title="Veri Kalitesi Raporu")
    table.add_column("Metrik", style="cyan")
    table.add_column("Değer", justify="right", style="green")

    rows = [
        ("Toplam çekilen kayıt", report.total_fetched),
        ("Toplam eklenen kayıt", report.total_inserted),
        ("Tekrarlı kayıt", report.total_duplicates),
        ("Hata sayısı", report.total_errors),
        ("Eksik alan oranı", f"{report.missing_field_ratio:.2%}"),
        ("Bilinmeyen lisanslı kayıt", report.unknown_license_count),
        ("Türkçeleştirilen kayıt", report.translated_count),
        ("İnceleme bekleyen AI çıktısı", report.pending_ai_review),
        ("Onaylanmış soru-cevap", report.approved_qa_count),
        ("Kaynak kaydı bulunmayan QA", report.orphan_qa_count),
    ]
    for label, value in rows:
        table.add_row(label, str(value))
    console.print(table)

    if report.by_source:
        src_table = Table(title="Kaynak Bazlı Dağılım")
        src_table.add_column("Kaynak", style="cyan")
        for col in ("inserted", "valid", "review", "rejected", "pending"):
            src_table.add_column(col, justify="right")
        for src, counts in report.by_source.items():
            src_table.add_row(
                src,
                *[
                    str(counts.get(c, 0))
                    for c in ("inserted", "valid", "review", "rejected", "pending")
                ],
            )
        console.print(src_table)


main = app

if __name__ == "__main__":
    app()
