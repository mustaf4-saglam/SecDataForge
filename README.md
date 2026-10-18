# SecDataForge

Açık ve yeniden kullanılabilir siber güvenlik veri seti üretim aracı.

SecDataForge, açık siber güvenlik kaynaklarından veri toplar, standartlaştırır,
tekrarları ayıklar, Türkçe açıklama ve soru-cevap örnekleri üretir, kalite
kontrollerinden geçirir ve LLM eğitimi/değerlendirmesi için JSONL ve CSV
formatında dışa aktarır. Bu proje bir chatbot değildir; amacı izlenebilir ve
kalitesi ölçülebilir veri setleri üretmektir.

## Teknoloji yığını

- Python 3.12+
- [httpx](https://www.python-httpx.org/): HTTP istemcisi
- [pydantic](https://docs.pydantic.dev/): veri modelleri ve doğrulama
- SQLite: kayıtlar, işlem durumu ve izlenebilirlik
- [typer](https://typer.tiangolo.com/): komut satırı arayüzü
- [Streamlit](https://streamlit.io/): yönetim paneli
- [pytest](https://docs.pytest.org/): testler
- [Ruff](https://docs.astral.sh/ruff/): biçimlendirme ve statik kontroller
- Ollama / OpenAI uyumlu API: isteğe bağlı LLM bağlantısı (kapalı varsayılan)

## Klasör yapısı

```text
secdataforge/
├── pyproject.toml
├── README.md
├── .env.example
├── .gitignore
├── src/secdataforge/      # paket kodu (cli, config, schemas, database, pipeline, ...)
├── app/dashboard.py       # Streamlit yönetim paneli
├── tests/                 # pytest birim testleri
├── examples/              # örnek JSON kayıtları
└── data/                  # raw / processed / exports (Git'e dahil değil)
```

## Kurulum

```bash
# 1. Depoyu klonlayın / klasöre geçin
cd SecDataForge

# 2. Sanal ortam oluşturun (önerilir)
python3 -m venv .venv
source .venv/bin/activate          # fish kabuğunda: source .venv/bin/activate.fish

# 3. Bağımlılıkları yükleyin (streamlit paneli dahil)
pip install -e .

# 4. Ortam dosyasını oluşturun
cp .env.example .env
# .env dosyasını düzenleyin (GITHUB_TOKEN gibi değerleri ekleyebilirsiniz).
```

`pip install -e .` komutu `secdataforge` konsol komutunu ve panel için
`streamlit` aracını kurar. Sanal ortam aktifken `secdataforge` ve `streamlit`
komutları doğrudan çalışır.

## İlk çalıştırma (örnek veri ile)

Gerçek API erişimi olmadan da tüm işlevleri doğrulayabilirsiniz:

```bash
# Veritabanını başlat ve kaynakları listele
secdataforge sources

# Örnek veriyle bir toplamayla başlatmak için pipeline'ı kullanabilirsiniz;
# aşağıdaki komut gerçek GitHub API'sine çağrı yapar (hız sınırı uygulanabilir).
secdataforge collect github --limit 50

# Tüm kaynaklar
secdataforge collect --limit 100

# Kalite raporu
secdataforge report

# Sadece 'valid' kayıtları dışa aktar
secdataforge export --format both --output data/exports --quality valid

# Tüm durumdaki kayıtları dışa aktar
secdataforge export --format jsonl --output data/exports/all.jsonl --quality all
```

Komutların `--help` çıktıları mevcuttur:

```bash
secdataforge --help
secdataforge collect --help
```

## Komut satırı komutları

| Komut | Açıklama |
|-------|----------|
| `secdataforge sources` | Yapılandırılan kaynakları ve son işlem durumlarını listeler |
| `secdataforge collect [kaynak] [--limit N] [--resume] [--full-history] [--since YYYY-MM-DD]` | Veri toplama hattını çalıştırır (`github`, `osv` veya `all`); `--resume` (varsayılan) son işlemin kaydettiği sayfa imlecinden devam eder; `--full-history` imleci yok sayar, baştan çeker; `--since YYYY-MM-DD` bu tarihten eski kayıtları atlar |
| `secdataforge validate` | Mevcut kayıtların kalitesini yeniden değerlendirir |
| `secdataforge enrich [--llm]` | LLM ile isteğe bağlı zenginleştirme (Türkçe çeviri, önlem, QA) |
| `secdataforge export [--format jsonl\|csv\|both] [--quality valid\|all] [--output DIR] [--source X]` | Kayıtları dışa aktarır |
| `secdataforge report` | Veri kalitesi raporunu gösterir |

## Kaynak yapılandırması

Bağlayıcılar `src/secdataforge/config.py` ve `.env` üzerinden yapılandırılır:

- `GITHUB_BASE_URL` — GitHub Global Security Advisories API (varsayılan: `https://api.github.com`)
- `GITHUB_TOKEN` — GitHub personal access token (opsiyonel, oran sınırını artırır)
- `OSV_BASE_URL` — OSV Vulnerability API (varsayılan: `https://api.osv.dev/v1`)
- `DEFAULT_RECORD_LIMIT`, `REQUEST_TIMEOUT`, `MAX_RETRIES`, `BACKOFF_FACTOR`

Bağlayıcılar sayfalama, zaman aşımı, sınırlı yeniden deneme (artan bekleme), HTTP 429
yönetimi ve idempotent (tekrar çalıştırılabilir) işlemleri destekler. Tüm veritabanı
kontrolsüz indirilmez; kayıt sınırı ve sayfalama ile sınırlandırılır.

### `collect` ek seçenekleri (GitHub için)

| Seçenek | Açıklama |
|---------|----------|
| `--resume` | (Varsayılan) Son işlemin kaydettiği sayfa imlecinden (`next_cursor`) devam eder. Sadece **yeni** kayıtları çeker. Kayıtlar dedupe edilerek eklenir. |
| `--full-history` | İmleci **yok sayar**, en yeniden başlayarak geriye doğru **tüm geçmişi** çeker. Kayıtlar dedupe edilir; zaten DB'de olanlar atlanır. Büyük limitlerle (ör. `--limit 5000`) tüm GitHub Advisory Database'i çekebilirsiniz. `--resume` ile çelişir; bu seçeneğe basılırsa `--resume` yoksayılır. |
| `--since YYYY-MM-DD` | Belirtilen tarihten (YYYY-MM-DD) **eski** kayıtları atlar (client-side filtre). `published_at` alanına göre filtreler. `--full-history` ile kombine edilebilir (ör. `--full-history --since 2024-01-01` → 2024'ten bugüne tüm geçmiş). |

**Örnekler:**

```bash
# Varsayılan: sadece yenileri (haftalık/periyodik kullanım)
secdataforge collect github --limit 500 --resume

# Tüm geçmişi baştan çek (tek seferlik, büyük limit)
secdataforge collect github --limit 5000 --full-history

# 2024'ten bugüne tüm geçmiş
secdataforge collect github --limit 5000 --full-history --since 2024-01-01

# Sadece 2025'ten bugüne (imleç yok, sadece filtre)
secdataforge collect github --limit 2000 --since 2025-01-01
```

OWASP bağlayıcısı sonraki bir aşamada planlanmıştır; yalnızca erişim ve içerik
kullanım koşulları doğrulanmış içerikler içe aktarılacaktır.

## LLM ayarları (isteğe bağlı, kapalı varsayılan)

LLM entegrasyonu varsayılan olarak kapalıdır ve uygulamanın diğer işlevleri
LLM olmadan da çalışmaya devam eder. `.env` üzerinden yapılandırın:

```ini
LLM_ENABLED=true
LLM_PROVIDER=gemini          # ollama | openai_compatible | gemini | claude | huggingface | evren
LLM_MODEL=gemini-1.5-flash
LLM_TEMPERATURE=0.0
LLM_TIMEOUT=120.0            # saniye; yavaş yerel modeller için artırın

# Sağlayıcıbazlı API anahtarlardan biri yeterli
GEMINI_API_KEY=              # https://aistudio.google.com/
CLAUDE_API_KEY=              # https://console.anthropic.com/
HUGGINGFACE_API_KEY=         # https://huggingface.co/settings/tokens
LLM_API_KEY=                 # openai_compatible (OpenAI, Mistral, vb.) için

# EVREN LLM API (Türkiye, SAYZEK ekosistemi; OpenAI uyumlu)
EVREN_API_KEY=               # EVREN hesabınızdan alın; ASLA koda/depoya yazmayın
EVREN_BASE_URL=https://evren-llmapi.ssyz.org.tr/v1
EVREN_MODEL=                 # boş bırakılırsa /models listesinden ilk model seçilir
EVREN_TERMS_URL=https://evren-llmapi.ssyz.org.tr
```

### Desteklenen LLM sağlayıcıları

| Sağlayıcı | `LLM_PROVIDER` | API anahtarı | Önerilen modeller |
|-----------|----------------|--------------|-------------------|
| **Ollama** (yerel) | `ollama` | Yok (localhost) | `llama3.2`, `mistral`, `qwen2.5` |
| **OpenAI uyumlu** | `openai_compatible` | `LLM_API_KEY` | `gpt-4o-mini`, `gpt-4o`, `mistral-large` |
| **Google Gemini** | `gemini` | `GEMINI_API_KEY` | `gemini-1.5-flash`, `gemini-1.5-pro` |
| **Anthropic Claude** | `claude` | `CLAUDE_API_KEY` | `claude-3-5-sonnet`, `claude-3-haiku` |
| **Hugging Face** (açık kaynak) | `huggingface` | `HUGGINGFACE_API_KEY` | `meta-llama/Llama-3.1-8B-Instruct`, `mistralai/Mistral-7B-Instruct-v0.3` |
| **EVREN** (Türkiye) | `evren` | `EVREN_API_KEY` | `/models` listesinden seçilir (tahmini ad YOK) |

**Hugging Face** ile erişebileceğiniz açık kaynak dağıtık modellerden bazıları:

- `meta-llama/Llama-3.1-8B-Instruct` — Meta'nın Llama 3.1 modeli
- `mistralai/Mistral-7B-Instruct-v0.3` — Mistral AI
- `Qwen/Qwen2.5-7B-Instruct` — Alibaba Qwen
- `deepseek-ai/DeepSeek-V3` — DeepSeek
- `google/gemma-2-9b-it` — Google Gemma

Binlerce model: https://huggingface.co/models?pipeline_tag=text-generation

**Kullanım örnekleri:**

```bash
# Yerel Ollama (varsayılan)
secdataforge enrich --llm --model llama3.2 --limit 10

# Google Gemini
secdataforge enrich --llm --provider gemini --model gemini-1.5-flash --limit 10

# Anthropic Claude
secdataforge enrich --llm --provider claude --model claude-3-5-sonnet-20241022 --limit 10

# Hugging Face açık kaynak model
secdataforge enrich --llm --provider huggingface --model meta-llama/Llama-3.1-8B-Instruct --limit 10

# OpenAI veya uyumlu API (Mistral, Groq, vb.)
secdataforge enrich --llm --provider openai_compatible --model gpt-4o-mini --limit 10
```

### EVREN entegrasyonu (Türkiye, SAYZEK)

EVREN, OpenAI uyumlu bir REST API'dir
(`https://evren-llmapi.ssyz.org.tr/v1`). Entegrasyon üç adımdır:

```bash
# 1) .env'e anahtarınızı ekleyin (koda asla yazmayın)
cp .env.example .env
# EVREN_API_KEY=... değerini .env içine girin

# 2) Kullanım şartlarını okuyup AÇIK onay verin (otomatik kabul YOK)
secdataforge evren-setup

# 3) Bağlantı + model listesi + kısa sohbet testini çalıştırın
secdataforge evren-test
# opsiyonel: --model <id>  veya  --no-chat

# 4) Kullanım
secdataforge enrich --llm --provider evren --limit 10
```

EVREN davranışları:

- **Model adı tahmin edilmez:** `EVREN_MODEL` boşsa model kimliği her zaman
  `GET /models` yanıtından seçilir. Listeyi `secdataforge evren-test` ile
  görebilirsiniz.
- **Kullanım şartları:** `enrich --provider evren` yalnızca `evren-setup`
  ile açık onay verildikten sonra çalışır. Onay kaydı yerel dosyada tutulur
  (`data/evren_terms_accepted.json`, `.gitignore`'da) ve **API anahtarı
  içermez** (yalnızca 12 karakterlik parmak izi).
- **Hata eşlemesi:** 401 (anahtar), 403 (şart/izin), 404 (endpoint/model),
  429 (kota) ve 5xx (servis) için açıklayıcı Türkçe mesaj üretilir.
- **Panel:** `streamlit run app/dashboard.py` → *LLM / EVREN* sekmesinde
  model listesi çekme, bağlantı testi, şart onayı ve zenginleştirme var.
  API anahtarı panele/tarayıcıya ASLA gönderilmez; yalnızca
  "tanımlı/tanımsız" gösterilir.
- **Kimlik doğrulama:** `Authorization: Bearer` ve `X-API-Key` başlıkları
  birlikte gönderilir.
- `response_format` desteklemeyen dağıtımlar için otomatik geri düşme vardır.

**Önemli notlar:**

- API anahtarları kod içine yazılmaz, sadece `.env` dosyasında tutulur
- Her sağlayıcı için `is_available()` kontrolü yapılır — anahtar yoksa açıklayıcı hata alırsınız
- Yavaş modeller için `LLM_TIMEOUT=300` gibi değerler kullanın
- Tüm çıktılar `review` kuyruğuna düşer; otomatik onay yok

Görevler: Türkçeleştirme, açıklama üretimi, kaynakla desteklenen soru-cevap
hazırlama, önlem önerisi ve sınıflandırma. Çıktılar yapılandırılmış JSON olarak
üretilir ve Pydantic ile doğrulanır. CVE kimlikleri, sürümler, tarihler, paket
isimleri ve önem derecesini değiştirmeye izin verilmez. Yalnızca JSON şemasına
uymak yetmez; kaynakla dayanak kontrolü, kalite filtreleri ve inceleme süreci
ayrı tutulur. LLM çıktıları varsayılan olarak inceleme kuyruğuna alır.

## Veri şeması

Ortak güvenlik duyurusu şeması (`src/secdataforge/schemas.py`):

| Alan | Tür | Açıklama |
|------|-----|----------|
| `record_id` | string | Uygulama içi benzersiz kimlik |
| `source` | string | Kaynak adı (`github`, `osv`, ...) |
| `source_id` | string | Kaynaktaki orijinal kimlik (GHSA / CVE / OSV) |
| `source_url` | string? | Kaynak bağlantısı |
| `license` | string? | İçerik lisansı |
| `license_status` | enum | `allowed` / `restricted` / `unknown` |
| `collected_at` | datetime | Toplanma tarihi |
| `published_at` | datetime? | Yayın tarihi |
| `modified_at` | datetime? | Son değişiklik tarihi |
| `title` | string? | Başlık |
| `description_original` | string? | Orijinal açıklama |
| `description_tr` | string? | Türkçe açıklama |
| `cve_ids` | [string]? | CVE kimlikleri |
| `cwe_ids` | [string]? | CWE kimlikleri |
| `affected_packages` | [string]? | Etkilenen paketler |
| `severity` | string? | Önem derecesi |
| `references` | [string]? | Referans bağlantılar |
| `remediation_tr` | string? | Türkçe önlem önerisi |
| `raw_hash` | string? | Ham veri SHA-256 özeti |
| `quality_status` | enum | `pending` / `valid` / `review` / `rejected` |
| `quality_issues` | [string]? | Tespit edilen kalite sorunları |

Ham yanıt `raw_records` tablosunda, normalize edilmiş veri
`security_advisories` tablosunda ayrı ayrı tutulur. AI üretilen soru-cevap
örnekleri `qa_pairs` tablosunda (soru, cevap, kaynak kimlikleri, dayanak alanları,
model, üretim zamanı, doğrulama durumu, insan inceleme bayrağı) saklanır.

Örnek kayıtlar `examples/` dizinindedir:
- `examples/sample_advisory.json`
- `examples/sample_qa.json`

## Lisans yaklaşımı

Kaynakları yalnızca HTTP ile alınabiliyor olmaları temel alınarak yeniden
dağıtılabilir kabul edilmez. Her kaynak için kullanım koşulları ve lisansı ayrı
değerlendirilir. Bilinmeyen veya uygun olmayan lisanslı içerikler varsayılan
olarak dışa aktarılabilir veri setine girmez; `license_status` `unknown` veya
`restricted` olan kayıtlar `review` (inceleme) durumunda tutulur ve
`--quality valid` dışa aktarımlarından çıkarıldıkları gibi kalır.

GitHub Global Security Advisories verisi, GitHub Advisory Database'ten gelir ve
CC-BY-4.0 lisansı ile yayımlanır (kaynak:
<https://github.com/github/advisory-database> — LICENSE.md). Atıf koşulu, her
kayıtta korunan `source_url` (GHSA sayfası) ve `license` alanıyla sağlanır.
Bu nedenle GitHub konektörü lisansı `CC-BY-4.0` / `allowed` olarak tanımlıdır.

OSV verisi farklı veritabanlarından harmanlandığı için tek ve doğrulanmış bir
lisans sunmaz; kayıtlar varsayılan olarak `unknown` işaretlenir ve inceleme
kuyruğunda tutulur. Veri setinizde OSV kullanacaksanız her kaynağın kullanım
koşullarını ayrıca değerlendirmeniz gerekir.

Lisans kararları konektör yapılandırmasında (`license`, `license_status`)
tutulur; `secdataforge validate` güncel politikayı mevcut kayıtlara da uygular
(ör. sonradan verilen bir lisans kararı eski kayıtları incelemeden çıkarır).

## Testler

```bash
pip install pytest ruff   # dev bağımlılıkları
pytest                    # tüm birim testleri
ruff check src/ tests/    # statik kontroller
ruff format src/ tests/   # biçimlendirme denetimi
```

Testler gerçek HTTP/API çağrısı yapmaz; sentetik veri ve mock bağlayıcılar
kullanılır. Canlı verilerden gelen sonuçlar testlerin tek doğru çıktısı olarak
sabitlenmez.

## Bilinen sınırlamalar

- Kimlik doğrulamasız GitHub isteklerinde saatlik 60 isteklik oran sınırı
  vardır (`GITHUB_TOKEN` ile daha yüksek sınır).
- OSV'in genel "liste tüm" endpoint'i yoktur; `cves`/`ghsas`/`package` filtreleri
  üzerinden sorgu yapılır.
- LLM entegrasyonu opsiyonel; yapılandırılmadığında çeviri/QA/önlem özellikleri
  devre dışı kalır.
- OWASP bağlayıcısı ilk sürümde dahil değildir.
- Türkçeleştirme ve LLM çıktıları otomatik olarak onaylanmaz; insansözlü
  inceleme kuyruğuna alınır.

## Geliştirici notları

- Tüm işlem hatı aşamaları ayrı modüldedir (`pipeline.py`, `exporters.py`,
  `quality.py`, `sources/`, `llm/`). Bir kaynak hata verdiğinde tüm hatayı
  çökmemesini sağlar; işlem devam ettirilebilir ve idempotent-dir.
- Yeni bir kaynak eklemek için `sources/base.py`'daki `BaseConnector` sınıfını
  miras alıp `fetch`, `normalize`, `enrich` metodlarını uygulamak yeterlidir.
- Gizli bilgiler `.env` dosyasında tutulur; `.env` Git'e eklenmez
  (`.gitignore`).
