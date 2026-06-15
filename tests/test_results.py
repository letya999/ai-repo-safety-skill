from ai_repo_safety.results import ScanReport, Finding, ToolRun


def test_scan_report_exit_codes() -> None:
    r = ScanReport(status="partial", target=".")
    r.tools.append(ToolRun(name="pip-audit", command=["pip-audit"], status="skipped", required=False, reason="network_required"))
    r.tools.append(ToolRun(name="bandit", command=["bandit"], status="passed", exit_code=0))
    assert r.exit_code(strict=False) == 0
    assert r.exit_code(strict=True) == 3

    r.findings.append(Finding(id="f-1", severity="high", category="forbidden_file", message="x", file=".env"))
    assert r.exit_code() == 1
    assert r.exit_code(strict=True) == 1

    r.errors.append("bandit crashed")
    assert r.exit_code() == 2

    err_report = ScanReport(status="error", target=".")
    assert err_report.exit_code() == 2


def test_scan_report_to_dict_roundtrip() -> None:
    r = ScanReport(status="passed", target="/tmp/x")
    r.tools.append(ToolRun(name="gitleaks", command=["gitleaks"], status="passed", exit_code=0))
    d = r.to_dict()
    assert d["status"] == "passed"
    assert d["target"] == "/tmp/x"
    assert d["tools"][0]["name"] == "gitleaks"
    assert d["findings"] == []
    assert d["errors"] == []
