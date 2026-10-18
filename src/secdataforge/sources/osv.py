"""OSV Vulnerability API bağlayıcısı.

Dokümantasyon: https://google.github.io/osv.dev/api/

Sorgular: POST /v1/query (CVE, GHSA veya paket/sürüm), GET /v1/vulns/{id}.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from ..config import settings
from ..schemas import LicenseStatus
from .base import BaseConnector, ConnectorConfig, FetchResult


class OSVConnector(BaseConnector):
    def __init__(self, config: ConnectorConfig | None = None) -> None:
        if config is None:
            config = ConnectorConfig(
                name="osv",
                base_url=settings.osv_base_url,
                license=None,
                license_status=LicenseStatus.unknown,
            )
        super().__init__(config)
        self._query_url = f"{config.base_url}/query"
        self._vuln_url = f"{config.base_url}/vulns"

    def fetch(self, limit: int | None = None, cursor: Any = None) -> FetchResult:
        limit = limit or self.config.record_limit
        # cursor: --resume ile string olarak da gelebilir
        start = int(cursor) if cursor is not None else 0
        errors: list[str] = []
        records: list[dict[str, Any]] = []

        # OSV list endpoint'i yoktur; yapılandırılmış kimlikler üzerinden sorgu yapılır.
        cves = self.config.filters.get("cves") or []
        ghsa_ids = self.config.filters.get("ghsas") or []
        queries: list[dict[str, Any]] = []
        for cve in cves:
            queries.append({"cve": cve})
        for ghsa in ghsa_ids:
            queries.append({"ghsa": ghsa})

        # Paket bazlı sorgu (opsiyonel)
        pkg = self.config.filters.get("package")
        version = self.config.filters.get("version")
        ecosystem = self.config.filters.get("ecosystem")
        if pkg:
            queries.append(
                {"package": {"name": pkg, "ecosystem": ecosystem or ""}, "version": version or ""}
            )

        next_cursor: int | None = None
        for idx in range(start, min(start + limit, len(queries))):
            query = queries[idx]
            try:
                response = self._request_with_retry("POST", self._query_url, json=query)
                if response.status_code != 200:
                    errors.append(f"OSV query HTTP {response.status_code} for {query}")
                    continue
                payload = response.json()
                vulns = payload.get("vulns") or []
                for vuln in vulns:
                    if isinstance(vuln, dict):
                        records.append(vuln)
                        if len(records) >= limit:
                            break
            except Exception as exc:
                errors.append(f"OSV query hatası ({query}): {exc}")
            if len(records) >= limit:
                break

        if start + limit < len(queries):
            next_cursor = start + limit

        return FetchResult(source="osv", records=records, errors=errors, next_cursor=next_cursor)

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        aliases = raw.get("aliases") or []
        cve_ids: list[str] = [a for a in aliases if isinstance(a, str) and a.startswith("CVE-")]
        ghsa_ids: list[str] = [a for a in aliases if isinstance(a, str) and a.startswith("GHSA-")]
        source_id = str(raw.get("id") or "")
        if not source_id and ghsa_ids:
            source_id = ghsa_ids[0]
        if not source_id and cve_ids:
            source_id = cve_ids[0]
        if not source_id:
            # Kimlik yoksa içerik özetinden deterministik bir yedek üret
            digest = hashlib.sha256(
                json.dumps(raw, ensure_ascii=False, sort_keys=True).encode("utf-8")
            ).hexdigest()
            source_id = f"auto-{digest[:12]}"

        packages: list[str] = []
        for affected in raw.get("affected") or []:
            if not isinstance(affected, dict):
                continue
            pkg = affected.get("package") or {}
            name = pkg.get("name")
            ecosystem = pkg.get("ecosystem")
            label = f"{name}@{ecosystem}" if name and ecosystem else name or ""
            if label:
                packages.append(label)

        severity = None
        sev_list = raw.get("severity") or []
        if sev_list and isinstance(sev_list, list) and sev_list:
            first = sev_list[0]
            if isinstance(first, dict):
                severity = first.get("score") or first.get("type")

        refs: list[str] = []
        for ref in raw.get("references") or []:
            if isinstance(ref, dict) and ref.get("url"):
                refs.append(ref["url"])

        published_at = self._parse_ts(raw.get("published"))
        modified_at = self._parse_ts(raw.get("modified"))

        return {
            "record_id": f"osv:{source_id}",
            "source": "osv",
            "source_id": source_id,
            "source_url": f"https://osv.dev/vulnerability/{source_id}",
            "license": None,
            "license_status": "unknown",
            "collected_at": None,
            "published_at": published_at.isoformat() if published_at else None,
            "modified_at": modified_at.isoformat() if modified_at else None,
            "title": raw.get("summary"),
            "description_original": raw.get("details") or raw.get("summary"),
            "description_tr": None,
            "cve_ids": cve_ids or None,
            "cwe_ids": None,
            "affected_packages": packages or None,
            "severity": severity,
            "references": refs or None,
            "remediation_tr": None,
            "raw_hash": None,
            "quality_status": "pending",
            "quality_issues": None,
        }

    def enrich(self, source_id: str) -> dict[str, Any] | None:
        url = f"{self._vuln_url}/{source_id}"
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
    def _parse_ts(value: Any) -> datetime | None:
        if not value:
            return None
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(
                timezone.utc
            )
        except Exception:
            return None
