"""Streamlit paneli duman testi (gerçek ağ/LLM çağrısı yok).

Eski hata: ``st.cache_resource`` ile paylaşılan DB bağlantısı her betik
çalıştırmasının sonunda kapatılıyordu; panel ikinci etkileşimde
"Cannot operate on a closed database" hatası veriyordu. Bu test paneli iki kez
çalıştırarak (rerun simülasyonu) hatanın geri dönmediğini doğrular.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("streamlit")

from streamlit.testing.v1 import AppTest  # noqa: E402

_DASHBOARD = Path(__file__).resolve().parent.parent / "app" / "dashboard.py"


def test_dashboard_renders_and_survives_rerun(tmp_path, monkeypatch):
    from secdataforge.config import settings

    # Testte kullanıcı veritabanına dokunmamak için geçici DB yolu kullan
    monkeypatch.setattr(settings, "db_path", tmp_path / "dashboard.db")

    at = AppTest.from_file(str(_DASHBOARD), default_timeout=60)
    at.run()
    assert not at.exception

    # Rerun simülasyonu: eski kod ikinci çalıştırmada kapalı bağlantıya erişirdi
    at.run()
    assert not at.exception

    # Temel panel öğeleri görünmeli
    assert any("SecDataForge" in t.value for t in at.title)
