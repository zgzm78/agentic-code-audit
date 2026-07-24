from __future__ import annotations

import json
from pathlib import Path

from agentic_code_audit.report_quality import analyze_report, scan_reports


def _write_report(
    root: Path,
    report_id: str,
    *,
    target: str,
    created_at: str,
    findings: list[dict],
    verification_results: list[dict],
) -> Path:
    report_dir = root / report_id
    report_dir.mkdir(parents=True)
    path = report_dir / "audit-report.json"
    path.write_text(
        json.dumps(
            {
                "input_source": {"original": target},
                "created_at": created_at,
                "dangerous_functions": [{"id": "anchor-1"}],
                "program_slices": [{"id": "slice-1"}],
                "candidates": [{"id": "candidate-1"}, {"id": "candidate-2"}],
                "aggregated_candidates": [{"id": "candidate-1"}],
                "findings": findings,
                "verification_results": verification_results,
            }
        ),
        encoding="utf-8",
    )
    return path


def test_analyze_report_measures_source_sink_flow_triage_and_dynamic_proof(tmp_path: Path) -> None:
    path = _write_report(
        tmp_path,
        "report-1",
        target="https://github.com/example/project.git",
        created_at="2026-07-20T10:00:00+00:00",
        findings=[
            {
                "risk_domain": "source_code",
                "source": "request.form['name']",
                "sink": "os.system",
                "flow_status": "propagated",
                "triage_verdict": "accept",
                "call_chain": ["route", "handler", "os.system"],
                "evidence_strength": "strong",
            },
            {"risk_domain": "dependency", "source": "", "sink": ""},
        ],
        verification_results=[{"status": "partial_dynamic_proof", "proof_level": "micro_proof"}],
    )

    quality = analyze_report(path)

    assert quality.target == "example/project"
    assert quality.findings == 2
    assert quality.source_code_findings == 1
    assert quality.source_sink_complete == 1
    assert quality.linked_flow_findings == 1
    assert quality.llm_triage_accepted == 1
    assert quality.call_chain_ge_3 == 1
    assert quality.dynamically_proven == 1
    assert quality.candidate_to_finding_rate == 1.0


def test_scan_reports_selects_latest_report_per_target_and_tolerates_invalid_json(tmp_path: Path) -> None:
    common_finding = [{"risk_domain": "source_code", "source": "input", "sink": "eval"}]
    _write_report(
        tmp_path,
        "older",
        target="https://github.com/example/project/tree/v1",
        created_at="2026-07-19T10:00:00+00:00",
        findings=common_finding,
        verification_results=[],
    )
    _write_report(
        tmp_path,
        "newer",
        target="https://github.com/example/project/tree/v2",
        created_at="2026-07-21T10:00:00+00:00",
        findings=common_finding,
        verification_results=[],
    )
    invalid_dir = tmp_path / "invalid"
    invalid_dir.mkdir()
    (invalid_dir / "audit-report.json").write_text("{not-json", encoding="utf-8")

    scan = scan_reports(tmp_path)

    assert [report.report_id for report in scan.reports] == ["newer"]
    assert len(scan.invalid_reports) == 1
    assert "漏洞挖掘质量基线" in scan.to_markdown()
