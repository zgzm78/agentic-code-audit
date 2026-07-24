from __future__ import annotations

from pathlib import Path

from agentic_code_audit.agents.mining import SliceAnalyzer
from agentic_code_audit.agents.verification import StaticVerifier
from agentic_code_audit.models import DangerousFunction, Finding, RouteSummary, SemanticIndex


def _anchor() -> DangerousFunction:
    return DangerousFunction(
        id="danger-1",
        file_path="app.py",
        line_start=4,
        function_name="ping",
        dangerous_api="os.system",
        category="command",
        snippet="os.system(cmd)",
        language="Python",
        sink="os.system",
        rule_vuln_type="command_injection",
        risk_domain="source_code",
        signal_kind="code_sink",
    )


def test_evidence_graph_marks_entry_tainted_flow(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "def ping():\n"
        "    raw = request.args.get('host')\n"
        "    cmd = raw.strip()\n"
        "    os.system(cmd)\n",
        encoding="utf-8",
    )
    semantic = SemanticIndex(
        routes=[RouteSummary(method="GET", route="/ping", handler="ping", file_path="app.py", line_start=1)]
    )

    anchor = _anchor()
    program_slice = SliceAnalyzer().analyze(tmp_path, [anchor], semantic, llm_client=None)[0]

    assert program_slice.slice_status == "entry_tainted_flow"
    assert program_slice.evidence_graph.status == "entry_tainted_flow"
    assert any(path.status == "proven" for path in program_slice.evidence_graph.paths)
    assert any(node.type == "entry" for node in program_slice.evidence_graph.nodes)


def test_evidence_graph_keeps_parameter_flow_unresolved(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("def ping(cmd):\n    os.system(cmd)\n", encoding="utf-8")
    anchor = _anchor()
    anchor.line_start = 2

    program_slice = SliceAnalyzer().analyze(tmp_path, [anchor], SemanticIndex(), llm_client=None)[0]

    assert program_slice.slice_status == "parameter_flow_unresolved"
    assert "caller_source_not_resolved" in program_slice.evidence_graph.gaps
    assert program_slice.evidence_graph.paths[0].status == "source_unresolved"


def test_evidence_graph_marks_unlinked_sink_when_context_source_is_unrelated(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "def ping():\n"
        "    raw = request.args.get('host')\n"
        "    cmd = 'uptime'\n"
        "    os.system(cmd)\n",
        encoding="utf-8",
    )

    program_slice = SliceAnalyzer().analyze(tmp_path, [_anchor()], SemanticIndex(), llm_client=None)[0]

    assert program_slice.source == ""
    assert program_slice.slice_status == "unlinked_sink"
    assert "source_to_sink_taint_not_proven" in program_slice.evidence_graph.gaps


def test_static_verifier_uses_evidence_graph_fact_path(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "def ping():\n"
        "    raw = request.args.get('host')\n"
        "    cmd = raw.strip()\n"
        "    os.system(cmd)\n",
        encoding="utf-8",
    )
    semantic = SemanticIndex(
        routes=[RouteSummary(method="GET", route="/ping", handler="ping", file_path="app.py", line_start=1)]
    )
    anchor = _anchor()
    program_slice = SliceAnalyzer().analyze(tmp_path, [anchor], semantic, llm_client=None)[0]
    finding = Finding(
        id="finding-1",
        vulnerability_type="command_injection",
        severity="high",
        title="command injection",
        description="source reaches os.system",
        file_path="app.py",
        line_start=4,
        source=program_slice.source,
        sink=program_slice.sink,
        function_name="ping",
        risk_domain="source_code",
        slice_id=program_slice.id,
        dangerous_function_id=program_slice.dangerous_function_id,
        evidence_graph=program_slice.evidence_graph,
        slice_status=program_slice.slice_status,
        evidence=["graph-backed source-to-sink path"],
    )

    result = StaticVerifier().verify(tmp_path, finding, program_slice=program_slice, dangerous_function=anchor)

    assert result.static_status == "plausible"
    assert result.reachability == "reachable"
    assert result.rule_checks["fact_taint_path"] is True


def test_static_verifier_does_not_promote_parameter_flow_to_plausible(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("def ping(cmd):\n    os.system(cmd)\n", encoding="utf-8")
    anchor = _anchor()
    anchor.line_start = 2
    program_slice = SliceAnalyzer().analyze(tmp_path, [anchor], SemanticIndex(), llm_client=None)[0]
    finding = Finding(
        id="finding-1",
        vulnerability_type="command_injection",
        severity="high",
        title="command injection",
        description="parameter reaches os.system",
        file_path="app.py",
        line_start=2,
        source=program_slice.source,
        sink=program_slice.sink,
        function_name="ping",
        risk_domain="source_code",
        evidence_graph=program_slice.evidence_graph,
        slice_status=program_slice.slice_status,
        evidence=["parameter reaches sink"],
    )

    result = StaticVerifier().verify(tmp_path, finding, program_slice=program_slice)

    assert result.static_status == "weak_static_proof"
    assert result.rule_checks["parameter_path"] is True
