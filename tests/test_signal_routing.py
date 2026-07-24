from agentic_code_audit.agents.mining import CandidateGenerator, SignalRouter, SliceAnalyzer
from agentic_code_audit.models import DangerousFunction


def _anchor(anchor_id: str, domain: str, kind: str) -> DangerousFunction:
    return DangerousFunction(
        id=anchor_id,
        file_path="src/app.py" if domain == "source_code" else "package.json",
        line_start=1,
        function_name="run" if domain == "source_code" else "",
        dangerous_api="eval" if domain == "source_code" else "CVE-2026-0001",
        category=domain,
        snippet="evidence",
        kind=kind,
        rule_vuln_type="code_execution" if domain == "source_code" else "dependency_vulnerability",
        anchor_category=domain,
        risk_domain=domain,
        evidence=["tool evidence"],
        tool="semgrep" if domain == "source_code" else "osv-scanner",
        tool_run_refs=["run-1"],
    )


def test_signal_router_separates_code_static_and_unsupported_signals() -> None:
    source = _anchor("source", "source_code", "tool_finding")
    dependency = _anchor("dependency", "dependency", "dependency_vulnerability")
    unsupported = _anchor("other", "environment", "tool_finding")

    streams = SignalRouter().route([source, dependency, unsupported])

    assert streams.source_code == [source]
    assert streams.dependency == [dependency]
    assert streams.unsupported == [unsupported]
    assert source.signal_kind == "code_sink"
    assert dependency.signal_kind == "dependency_advisory"


def test_static_evidence_does_not_create_fake_call_chain_or_use_llm_review() -> None:
    dependency = _anchor("dependency", "dependency", "dependency_vulnerability")
    streams = SignalRouter().route([dependency])
    slices = SliceAnalyzer().build_static_slices(streams.static_evidence)

    candidates = CandidateGenerator().generate_static(slices)

    assert slices[0].call_chain == []
    assert slices[0].data_flow == []
    assert candidates[0].candidate_source == "tool"
    assert candidates[0].signal_kind == "dependency_advisory"
    assert candidates[0].risk_domain == "dependency"
