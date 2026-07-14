"""
CVE matching against the official NVD (National Vulnerability Database) REST API v2.0.

Design notes:
- No API key is required, but the public rate limit is 5 requests / 30s.
  Supplying a free NVD API key (env var NVD_API_KEY) raises that to 50/30s.
  NEVER hardcode the key here — it is read from the environment only.
- Results are cached locally in SQLite for 7 days to avoid re-querying the
  same service/version repeatedly across scans.
- Network/parse failures degrade gracefully (return no CVEs) rather than
  crashing the scan — a CVE lookup failure should never take down the tool.
"""

import json
import logging
import os
import sqlite3
import time
from pathlib import Path
from typing import List, Optional

import requests

from src.core.models import CVEFinding, Severity

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_DB_PATH = Path.home() / ".security_toolkit" / "cve_cache.db"
CACHE_TTL_SECONDS = 7 * 24 * 60 * 60  # 7 days
_UNAUTHENTICATED_DELAY = 6.0  # seconds; keeps us under 5 req/30s
_AUTHENTICATED_DELAY = 0.6  # seconds; keeps us under 50 req/30s


class CVEMatcher:
    """Looks up CVEs for a given service/version search term, with caching."""

    def __init__(self, api_key: Optional[str] = None, timeout: int = 15, max_results: int = 10):
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self.timeout = timeout
        self.max_results = max_results
        self._rate_limit_delay = _AUTHENTICATED_DELAY if self.api_key else _UNAUTHENTICATED_DELAY
        self._last_request_time = 0.0
        self._init_cache()

    # ------------------------------------------------------------- public

    def lookup(self, search_term: str) -> List[CVEFinding]:
        search_term = (search_term or "").strip()
        if len(search_term) < 3:
            return []  # too short to produce meaningful NVD results

        cached = self._get_cached(search_term)
        if cached is not None:
            return cached

        findings = self._query_nvd(search_term)
        self._set_cache(search_term, findings)
        return findings

    # ------------------------------------------------------------- cache

    def _init_cache(self) -> None:
        CACHE_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(CACHE_DB_PATH) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cve_cache (
                    search_term TEXT PRIMARY KEY,
                    result_json TEXT NOT NULL,
                    cached_at REAL NOT NULL
                )
                """
            )

    def _get_cached(self, search_term: str) -> Optional[List[CVEFinding]]:
        with sqlite3.connect(CACHE_DB_PATH) as conn:
            row = conn.execute(
                "SELECT result_json, cached_at FROM cve_cache WHERE search_term = ?",
                (search_term,),
            ).fetchone()
        if not row:
            return None
        result_json, cached_at = row
        if time.time() - cached_at > CACHE_TTL_SECONDS:
            return None
        try:
            return self._findings_from_json(result_json)
        except (json.JSONDecodeError, KeyError, ValueError):
            return None  # corrupt cache entry — treat as a miss

    def _set_cache(self, search_term: str, findings: List[CVEFinding]) -> None:
        with sqlite3.connect(CACHE_DB_PATH) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO cve_cache (search_term, result_json, cached_at) VALUES (?, ?, ?)",
                (search_term, self._findings_to_json(findings), time.time()),
            )

    @staticmethod
    def _findings_to_json(findings: List[CVEFinding]) -> str:
        payload = [
            {
                "cve_id": f.cve_id,
                "description": f.description,
                "severity": f.severity.value,
                "cvss_score": f.cvss_score,
                "published_date": f.published_date,
                "references": f.references,
            }
            for f in findings
        ]
        return json.dumps(payload)

    @staticmethod
    def _findings_from_json(raw: str) -> List[CVEFinding]:
        payload = json.loads(raw)
        return [
            CVEFinding(
                cve_id=item["cve_id"],
                description=item["description"],
                severity=Severity(item["severity"]),
                cvss_score=item.get("cvss_score"),
                published_date=item.get("published_date"),
                references=item.get("references", []),
            )
            for item in payload
        ]

    # --------------------------------------------------------------- NVD

    def _query_nvd(self, search_term: str) -> List[CVEFinding]:
        self._respect_rate_limit()
        headers = {"apiKey": self.api_key} if self.api_key else {}
        params = {"keywordSearch": search_term, "resultsPerPage": self.max_results}

        try:
            resp = requests.get(NVD_API_URL, headers=headers, params=params, timeout=self.timeout)
        except requests.RequestException as exc:
            logger.warning("NVD request failed for %r: %s", search_term, exc)
            return []

        if resp.status_code == 429:
            logger.warning("NVD rate limit hit; backing off and skipping this lookup.")
            time.sleep(self._rate_limit_delay * 2)
            return []
        if resp.status_code != 200:
            logger.warning("NVD returned HTTP %s for %r", resp.status_code, search_term)
            return []

        try:
            data = resp.json()
        except ValueError:
            logger.warning("NVD returned non-JSON response for %r", search_term)
            return []

        return [self._parse_vulnerability(v) for v in data.get("vulnerabilities", [])]

    def _respect_rate_limit(self) -> None:
        elapsed = time.time() - self._last_request_time
        if elapsed < self._rate_limit_delay:
            time.sleep(self._rate_limit_delay - elapsed)
        self._last_request_time = time.time()

    @staticmethod
    def _parse_vulnerability(vuln_wrapper: dict) -> CVEFinding:
        cve = vuln_wrapper.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")

        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available.",
        )

        cvss_score, severity = CVEMatcher._extract_cvss(cve.get("metrics", {}))
        references = [r.get("url") for r in cve.get("references", []) if r.get("url")]

        return CVEFinding(
            cve_id=cve_id,
            description=description[:500],
            severity=severity,
            cvss_score=cvss_score,
            published_date=cve.get("published"),
            references=references[:5],
        )

    @staticmethod
    def _extract_cvss(metrics: dict):
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if entries:
                data = entries[0].get("cvssData", {})
                score = data.get("baseScore")
                sev_str = entries[0].get("baseSeverity") or data.get("baseSeverity")
                return score, CVEMatcher._severity_from_string(sev_str, score)
        return None, Severity.UNKNOWN

    @staticmethod
    def _severity_from_string(sev_str: Optional[str], score: Optional[float]) -> Severity:
        if sev_str:
            try:
                return Severity(sev_str.upper())
            except ValueError:
                pass
        if score is None:
            return Severity.UNKNOWN
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        return Severity.LOW
