"""GitHub Global Security Advisories API bağlayıcısı.

Dokümantasyon: https://docs.github.com/en/rest/security-advisories/global-advisories

Not: Kimlik doğrulamasız isteklerde saatlik 60 isteklik oran sınırı vardır.
GITHUB_TOKEN ayarlanırsa sınır daha geniş olur.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from datetime import datetime, timezone
from typing import Any

import httpx

from ..config import settings
from ..schemas import LicenseStatus
from .base import BaseConnector, ConnectorConfig, FetchResult


class GitHubAdvisoriesConnector(BaseConnector):
    def __init__(self, config: ConnectorConfig | None = None) -> None:
        if config is None:
            config = ConnectorConfig(
                name="github",
                base_url=settings.github_base_url,
                # GitHub Advisory Database CC-BY-4.0 lisanslıdır
                # (https://github.com/github/advisory-database — LICENSE.md).
                # Atıf koşulu, her kayıtta korunan `source_url` ve `license`
                # alanlarıyla sağlanır.
                license="CC-BY-4.0",
                license_status=LicenseStatus.allowed,
            )
        super().__init__(config)
        self._endpoint = f"{config.base_url}/advisories"

    def fetch(self, limit: int | None = None, cursor: Any = None) -> FetchResult:
        limit = limit or self.config.record_limit
        # cursor: --resume ile string olarak gelebilir (after=... değeridir)
        after_cursor = cursor if cursor is not None else None
        params: dict[str, Any] = {
            "per_page": min(100, limit),
            "type": "reviewed",
        }
        if after_cursor is not None:
            # Cursor (after) varsa sayfa numarası yerine after kullanılır
            params["after"] = after_cursor
        else:
            params["page"] = 1
        # İsteğe bağlı filtreler
        for key in ("severity", "ecosystem", "package", "cve", "ghsa"):
            if key in self.config.filters:
                params[key] = self.config.filters[key]

        errors: list[str] = []
        records: list[dict[str, Any]] = []
        next_cursor: str | None = None

        try:
            response = self._request_with_retry("GET", self._endpoint, params=params)
            if response.status_code != 200:
                errors.append(f"GitHub API HTTP {response.status_code}: {response.text[:200]}")
                return FetchResult(source="github", records=[], errors=errors, next_cursor=None)

            payload = response.json()
            if not isinstance(payload, list):
                errors.append("GitHub API beklenmeyen yanıt formatı (liste bekleniyordu)")
                return FetchResult(source="github", records=[], errors=errors, next_cursor=None)

            for item in payload:
                if isinstance(item, dict):
                    records.append(item)
                if len(records) >= limit:
                    break

            # Sayfalama: Link başlığından 'next' urokunun after cursor'unu çıkar
            next_cursor = self._next_page(response)
        except Exception as exc:  # hata yakalanıp pipeline'a iletilir
            errors.append(f"GitHub fetch hatası: {exc}")

        return FetchResult(source="github", records=records, errors=errors, next_cursor=next_cursor)

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        identifiers = raw.get("identifiers") or []
        cve_ids: list[str] = []
        source_id = str(raw.get("ghsa_id") or raw.get("id") or "")
        if not source_id:
            # Kimlik yoksa içerik özetinden deterministik bir yedek üret
            digest = hashlib.sha256(
                json.dumps(raw, ensure_ascii=False, sort_keys=True).encode("utf-8")
            ).hexdigest()
            source_id = f"auto-{digest[:12]}"
        for ident in identifiers:
            if isinstance(ident, dict):
                if ident.get("type") == "CVE" and ident.get("value"):
                    cve_ids.append(ident["value"])
                if ident.get("type") == "GHSA" and ident.get("value") and not source_id:
                    source_id = ident["value"]

        refs: list[str] = []
        for ref in raw.get("references") or []:
            if isinstance(ref, dict) and ref.get("url"):
                refs.append(ref["url"])
            elif isinstance(ref, str):
                refs.append(ref)

        packages: list[str] = []
        for vuln in raw.get("vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            pkg = vuln.get("package") or {}
            name = pkg.get("name")
            ecosystem = pkg.get("ecosystem")
            label = f"{name}@{ecosystem}" if name and ecosystem else name or ""
            if label:
                packages.append(label)

        published_at = None
        modified_at = None
        for field, target in (("published_at", "published_at"), ("updated_at", "modified_at")):
            value = raw.get(field)
            if value:
                try:
                    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                    if target == "published_at":
                        published_at = dt
                    else:
                        modified_at = dt
                except Exception:
                    pass

        return {
            "record_id": f"gh:{source_id}",
            "source": "github",
            "source_id": source_id,
            "source_url": f"https://github.com/advisories/{source_id}" if source_id else None,
            "license": None,
            "license_status": "unknown",
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "published_at": published_at.isoformat() if published_at else None,
            "modified_at": modified_at.isoformat() if modified_at else None,
            "title": raw.get("summary") or raw.get("title"),
            "description_original": raw.get("description"),
            "description_tr": None,
            "cve_ids": cve_ids or None,
            "cwe_ids": None,
            "affected_packages": packages or None,
            "severity": raw.get("severity"),
            "references": refs or None,
            "remediation_tr": None,
            "raw_hash": None,
            "quality_status": "pending",
            "quality_issues": None,
        }

    def enrich(self, source_id: str) -> dict[str, Any] | None:
        """Tek bir GHSA kimliğinin ayrıntılarını döndürür."""
        url = f"{self._endpoint}/{source_id}"
        try:
            response = self._request_with_retry("GET", url)
            if response.status_code == 200:
                return response.json()
            if response.status_code == 404:
                return None
        except Exception:
            return None
        return None

    @staticmethod
    def _next_page(response: httpx.Response) -> str | None:
        """Link başlığından rel="next" içeren URL'nin after=cursor değerini çıkarır.

        GitHub /advisories endpoint'i sayfa numarası yerine after=cursor kullanır.
        Link formatı: <.../advisories?per_page=100&type=reviewed&after=XYZ>; rel="next"

        Cursor Link başlığında URL-encoded gelir (örn. %3D%3D → ==).
        API'ye tekrar gönderirken httpx tekrar encode eder; bu yüzden
        önce decode edip **ham cursor** döndürürüz.
        """
        link = response.headers.get("Link", "")
        if 'rel="next"' not in link:
            return None
        m = re.search(r"after=([^&>]+)", link)
        if m:
            # URL-decode: httpx query param'a koyduğunda tekrar encode edecek
            return urllib.parse.unquote(m.group(1))
        return None
