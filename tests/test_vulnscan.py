from secrets_scanner import report
from secrets_scanner.vulnscan import ToolResult, parse_lynis_report, parse_trivy_json

LYNIS_DAT = """\
# Lynis Report
hardening_index=62
warning[]=AUTH-9286|Found accounts without expire date|-|-|
suggestion[]=SSH-7408|Consider hardening SSH configuration|PermitRootLogin (set YES to NO)|Set PermitRootLogin no|
suggestion[]=PKGS-7392|Update your system with apt-get update, apt-get upgrade|-|-|
"""

TRIVY_DOC = {
    "Metadata": {"OS": {"Family": "debian", "Name": "12.5"}},
    "Results": [
        {"Target": "debian 12.5", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2024-0002", "PkgName": "libssl3", "InstalledVersion": "3.0.11",
             "FixedVersion": "3.0.13", "Severity": "HIGH", "Title": "openssl issue"},
            {"VulnerabilityID": "CVE-2024-0001", "PkgName": "bash", "InstalledVersion": "5.2",
             "Severity": "LOW"},
            {"VulnerabilityID": "CVE-2024-0003", "PkgName": "libc6", "InstalledVersion": "2.36",
             "FixedVersion": "2.36-9", "Severity": "CRITICAL"},
        ]},
        {"Target": "debian 12.5", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2024-0002", "PkgName": "libssl3", "InstalledVersion": "3.0.11",
             "FixedVersion": "3.0.13", "Severity": "HIGH"},
        ]},
        {"Target": "usr/lib/python3/dist-packages", "Vulnerabilities": None},
    ],
}


def test_parse_lynis_report():
    data = parse_lynis_report(LYNIS_DAT)
    assert data["hardening_index"] == 62
    assert [w["id"] for w in data["warnings"]] == ["AUTH-9286"]
    ssh, pkgs = data["suggestions"]
    assert ssh["solution"] == "Set PermitRootLogin no" and "solution" not in pkgs


def test_parse_trivy_dedupes_and_sorts_by_severity():
    data = parse_trivy_json(TRIVY_DOC)
    assert [v["id"] for v in data["vulnerabilities"]] == ["CVE-2024-0003", "CVE-2024-0002", "CVE-2024-0001"]
    assert data["counts"]["CRITICAL"] == 1 and data["counts"]["HIGH"] == 1 and data["counts"]["LOW"] == 1
    assert data["vulnerabilities"][2]["fixed"] is None


def test_markdown_report_includes_every_section():
    tools = [
        ToolResult("lynis", "ok", data=parse_lynis_report(LYNIS_DAT)),
        ToolResult("trivy", "ok", data=parse_trivy_json(TRIVY_DOC)),
    ]
    md = report.to_markdown(report.build([], tools))
    assert "index 62/100" in md and "CVE-2024-0003" in md and "no fix yet" in md
    assert "Set PermitRootLogin no" in md and "Nothing flagged." in md


def test_skipped_tool_is_reported_not_fatal():
    md = report.to_markdown(report.build([], [ToolResult("trivy", "skipped", "not installed")]))
    assert "| trivy | skipped: not installed |" in md
