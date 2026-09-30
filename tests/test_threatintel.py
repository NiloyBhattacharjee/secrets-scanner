import json
import os
import time

import pytest

from secrets_scanner import report, threatintel
from secrets_scanner.vulnscan import ToolResult, parse_trivy_json

KEV_DOC = {
    "catalogVersion": "2026.09.30",
    "vulnerabilities": [
        {"cveID": "CVE-2024-0001", "vulnerabilityName": "Bash RCE", "dateAdded": "2024-05-01",
         "dueDate": "2024-05-22", "requiredAction": "Apply vendor updates.",
         "knownRansomwareCampaignUse": "Known"},
        {"cveID": "CVE-2023-9999", "vulnerabilityName": "Other", "dateAdded": "2023-01-01",
         "requiredAction": "Patch.", "knownRansomwareCampaignUse": "Unknown"},
    ],
}
KEV_RAW = json.dumps(KEV_DOC).encode()

TRIVY_DOC = {"Metadata": {"OS": {"Family": "debian", "Name": "12"}}, "Results": [{"Target": "debian", "Vulnerabilities": [
    {"VulnerabilityID": "CVE-2024-0003", "PkgName": "libc6", "InstalledVersion": "2.36", "FixedVersion": "2.36-9",
     "Severity": "CRITICAL"},
    {"VulnerabilityID": "CVE-2024-0002", "PkgName": "libssl3", "InstalledVersion": "3.0.11", "FixedVersion": "3.0.13",
     "Severity": "HIGH"},
    {"VulnerabilityID": "CVE-2024-0001", "PkgName": "bash", "InstalledVersion": "5.2", "Severity": "LOW"},
]}]}


class FakeFetch:
    def __init__(self, *responses):
        self.responses, self.urls = list(responses), []

    def __call__(self, url):
        self.urls.append(url)
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def test_parse_kev():
    kev = threatintel.parse_kev(KEV_DOC)
    assert kev["CVE-2024-0001"]["ransomware"] is True
    assert kev["CVE-2023-9999"]["ransomware"] is False


def test_kev_downloads_then_uses_fresh_cache(tmp_path):
    fetch = FakeFetch(KEV_RAW)
    first = threatintel.load_kev(cache_dir=tmp_path, fetch=fetch)
    second = threatintel.load_kev(cache_dir=tmp_path, fetch=fetch)
    assert (first.source, second.source, first.version) == ("download", "cache", "2026.09.30")
    assert len(fetch.urls) == 1


def test_kev_offline_falls_back_to_stale_cache(tmp_path):
    cache = tmp_path / "kev.json"
    cache.write_bytes(KEV_RAW)
    old = time.time() - 3 * 86400
    os.utime(cache, (old, old))
    cat = threatintel.load_kev(cache_dir=tmp_path, fetch=FakeFetch(OSError("no network")))
    assert cat.source == "stale-cache" and round(cat.age_hours) == 72


def test_kev_offline_without_cache_is_an_error(tmp_path):
    with pytest.raises(threatintel.IntelError):
        threatintel.load_kev(cache_dir=tmp_path, fetch=FakeFetch(OSError("no network")))


def test_kev_from_file(tmp_path):
    path = tmp_path / "my-kev.json"
    path.write_bytes(KEV_RAW)
    assert threatintel.load_kev(str(path)).source == "file"


def test_epss_batches_requests():
    cves = [f"CVE-2024-{i:04d}" for i in range(150)]
    batch = lambda ids: json.dumps({"data": [{"cve": c, "epss": "0.5", "percentile": "0.9"} for c in ids]}).encode()
    fetch = FakeFetch(batch(sorted(cves)[:100]), batch(sorted(cves)[100:]))
    scores = threatintel.fetch_epss(cves, fetch=fetch)
    assert len(fetch.urls) == 2 and len(scores) == 150 and scores["CVE-2024-0007"]["score"] == 0.5


def test_enrich_puts_kev_first_then_epss_then_severity():
    vulns = parse_trivy_json(TRIVY_DOC)["vulnerabilities"]
    epss = {"CVE-2024-0002": {"score": 0.9, "percentile": 0.99}}
    threatintel.enrich(vulns, threatintel.parse_kev(KEV_DOC), epss)
    # LOW-severity bash is exploited in the wild, so it outranks the CRITICAL one.
    assert [v["id"] for v in vulns] == ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"]


def test_report_shows_exploited_section_and_columns():
    data = parse_trivy_json(TRIVY_DOC)
    threatintel.enrich(data["vulnerabilities"], threatintel.parse_kev(KEV_DOC),
                       {"CVE-2024-0002": {"score": 0.123, "percentile": 0.9}})
    data["kev"] = {"status": "ok", "source": "download", "version": "x", "age_hours": 0, "size": 2}
    data["epss"] = {"status": "ok"}
    md = report.to_markdown(report.build([], [ToolResult("trivy", "ok", data=data)]))
    assert "| Actively exploited (CISA KEV) | **1 CVEs**, 1 used in ransomware |" in md
    assert "## Actively exploited (CISA KEV)" in md and "Apply vendor updates." in md
    assert "| KEV | EPSS (30-day) |" in md and "12.3%" in md


def test_report_notes_failed_kev_download():
    data = parse_trivy_json(TRIVY_DOC)
    data["kev"] = {"status": "error", "detail": "no network"}
    md = report.to_markdown(report.build([], [ToolResult("trivy", "ok", data=data)]))
    assert "not checked: no network" in md and "## Actively exploited" not in md
