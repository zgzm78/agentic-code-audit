from __future__ import annotations

from typing import Any

from agentic_code_audit.agents.mining import LLMCandidateReviewer
from agentic_code_audit.models import VulnerabilityCandidate


class _Response:
    def __init__(self, content: str, ok: bool = True) -> None:
        self.content = content
        self.ok = ok
        self.error = ""


class _LLM:
    enabled = True

    def __init__(self, content: str, *, ok: bool = True) -> None:
        self.content = content
        self.ok = ok

    def chat(self, *_args: Any, **_kwargs: Any) -> _Response:
        return _Response(self.content, self.ok)


def _candidate(**overrides: Any) -> VulnerabilityCandidate:
    base = {
        "id": "candidate-1",
        "slice_id": "slice-1",
        "title": "command injection",
        "vulnerability_type": "command_injection",
        "severity": "high",
        "file_path": "app.py",
        "line_start": 12,
        "description": "request input reaches os.system",
        "function_name": "handler",
        "trigger_conditions": ["request argument controls command"],
        "evidence": ["source to sink"],
        "source": "request.args.get",
        "sink": "os.system",
        "risk_domain": "source_code",
        "signal_kind": "code_sink",
        "flow_status": "propagated",
        "source_variables": ["raw"],
        "sink_variables": ["command"],
        "evidence_refs": ["slice-1"],
    }
    base.update(overrides)
    return VulnerabilityCandidate(**base)


def test_llm_triage_accepts_structural_source_candidate() -> None:
    candidate = _candidate()
    reviewer = LLMCandidateReviewer(_LLM('[{"verdict":"accept","reason":"coherent trace"}]'))

    reviewed = reviewer.review_batch([candidate], reviewer.llm_client)[0]

    assert reviewed.valid is True
    assert reviewed.triage_verdict == "accept"
    assert reviewed.confidence > 0.5


def test_llm_triage_rejects_candidate() -> None:
    candidate = _candidate()
    reviewer = LLMCandidateReviewer(_LLM('[{"verdict":"reject","reason":"sanitized before sink"}]'))

    reviewed = reviewer.review_batch([candidate], reviewer.llm_client)[0]

    assert reviewed.valid is False
    assert reviewed.triage_verdict == "reject"
    assert reviewed.validity == "rejected"
    assert reviewed.candidate_state == "rejected"
    assert "llm_rejected" in reviewed.invalid_reason


def test_llm_triage_needs_more_context_is_fail_closed() -> None:
    candidate = _candidate()
    reviewer = LLMCandidateReviewer(
        _LLM('[{"verdict":"needs_more_context","reason":"source not proven","missing_context":["caller"]}]')
    )

    reviewed = reviewer.review_batch([candidate], reviewer.llm_client)[0]

    assert reviewed.valid is False
    assert reviewed.triage_verdict == "needs_more_context"
    assert reviewed.validity == "needs_context"
    assert reviewed.candidate_state == "needs_context"
    assert reviewed.triage_missing_context == ["caller"]


def test_llm_triage_invalid_json_is_fail_closed() -> None:
    candidate = _candidate()
    reviewer = LLMCandidateReviewer(_LLM("not json"))

    reviewed = reviewer.review_batch([candidate], reviewer.llm_client)[0]

    assert reviewed.valid is False
    assert reviewed.triage_verdict == "needs_more_context"
    assert reviewed.validity == "needs_context"
    assert reviewed.candidate_state == "needs_context"
    assert reviewed.triage_reason == "llm_triage_parse_error"


def test_llm_triage_accept_without_structural_trace_is_rejected() -> None:
    candidate = _candidate(source="", flow_status="sink_unlinked", flow_gaps=["source_sink_variable_not_linked"])
    reviewer = LLMCandidateReviewer(_LLM('[{"verdict":"accept","reason":"looks risky"}]'))

    reviewed = reviewer.review_batch([candidate], reviewer.llm_client)[0]

    assert reviewed.valid is False
    assert reviewed.triage_verdict == "needs_more_context"
    assert reviewed.validity == "needs_context"
    assert reviewed.candidate_state == "needs_context"
    assert reviewed.triage_reason == "llm_accept_missing_source_or_sink"
