from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class InputSource:
    original: str
    kind: str
    local_path: str
    workspace: str = ""
    cloned: bool = False
    commit: str = ""


@dataclass
class AgentEvent:
    agent: str
    action: str
    status: str
    phase: str = ""
    detail: str = ""
    started_at: str = field(default_factory=utc_now)
    finished_at: str | None = None


@dataclass
class TaskRecord:
    id: str
    target: str
    mode: str
    status: str
    target_type: str = "unknown"
    commit: str = ""
    llm_provider: str = "deepseek"
    llm_model: str = "deepseek-v4-pro"
    model: str = ""
    runtime_url: str = ""
    current_agent: str = ""
    current_phase: str = ""
    progress_done: int = 0
    progress_total: int = 0
    report_dir: str = ""
    json_report: str = ""
    markdown_report: str = ""
    error: str = ""
    created_at: str = field(default_factory=utc_now)
    started_at: str | None = None
    finished_at: str | None = None


@dataclass
class AgentEventRecord:
    task_id: str
    sequence: int
    agent: str
    event_type: str
    message: str
    phase: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now)


@dataclass
class ArtifactRecord:
    id: str
    kind: str
    path: str
    task_id: str = ""
    sha256: str = ""
    size_bytes: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now)


@dataclass
class ToolRunRecord:
    run_id: str
    task_id: str
    tool: str
    status: str
    command: list[str] = field(default_factory=list)
    exit_code: int | None = None
    duration_ms: int | None = None
    stdout_artifact_id: str = ""
    stderr_artifact_id: str = ""
    parsed_artifact_id: str = ""
    summary: str = ""
    cache_key: str = ""
    cache_hit: bool = False
    data: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now)


@dataclass
class ProjectProfile:
    root: str
    languages: dict[str, int] = field(default_factory=dict)
    frameworks: list[str] = field(default_factory=list)
    package_files: list[str] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)
    high_risk_files: list[str] = field(default_factory=list)
    total_files: int = 0
    scanned_files: int = 0
    attack_surfaces: list[str] = field(default_factory=list)
    recommended_tools: list[str] = field(default_factory=list)
    project_type: str = "unknown"
    build_entries: list[dict[str, Any]] = field(default_factory=list)
    runtime_entries: list[dict[str, Any]] = field(default_factory=list)
    test_entries: list[dict[str, Any]] = field(default_factory=list)
    service_entries: list[dict[str, Any]] = field(default_factory=list)
    library_entries: list[dict[str, Any]] = field(default_factory=list)
    dependency_files: list[str] = field(default_factory=list)
    container_files: list[str] = field(default_factory=list)
    ci_files: list[str] = field(default_factory=list)
    config_files: list[str] = field(default_factory=list)
    environment_requirements: list[dict[str, Any]] = field(default_factory=list)
    verification_entries: list[dict[str, Any]] = field(default_factory=list)
    non_runnable_reasons: list[str] = field(default_factory=list)
    weak_verification_strategies: list[str] = field(default_factory=list)
    tool_availability: list[dict[str, Any]] = field(default_factory=list)
    recommended_tool_details: list[dict[str, Any]] = field(default_factory=list)
    dependency_findings_summary: list[dict[str, Any]] = field(default_factory=list)
    attack_priorities: list[str] = field(default_factory=list)
    verification_hints: list[str] = field(default_factory=list)
    recon_evidence_refs: list[str] = field(default_factory=list)
    profile_summary: dict[str, Any] = field(default_factory=dict)


@dataclass
class FunctionSummary:
    name: str
    file_path: str
    line_start: int
    signature: str
    summary: str
    tags: list[str] = field(default_factory=list)


@dataclass
class RouteSummary:
    method: str
    route: str
    handler: str
    file_path: str
    line_start: int


@dataclass
class SemanticIndex:
    functions: list[FunctionSummary] = field(default_factory=list)
    routes: list[RouteSummary] = field(default_factory=list)
    source_symbols: list[str] = field(default_factory=list)
    sink_symbols: list[str] = field(default_factory=list)
    module_summaries: dict[str, str] = field(default_factory=dict)


@dataclass
class ToolResult:
    tool: str
    status: str
    run_id: str = ""
    command: list[str] = field(default_factory=list)
    summary: str = ""
    raw: Any = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    exit_code: int | None = None
    duration_ms: int | None = None
    stdout_artifact_id: str = ""
    stderr_artifact_id: str = ""
    parsed_artifact_id: str = ""
    cache_key: str = ""
    cache_hit: bool = False
    artifact_records: list[ArtifactRecord] = field(default_factory=list)
    started_at: str = field(default_factory=utc_now)
    finished_at: str | None = None


@dataclass
class ChainNode:
    id: str
    label: str
    type: str
    file_path: str = ""
    line: int | None = None
    detail: str = ""


@dataclass
class ChainEdge:
    source: str
    target: str
    type: str
    label: str = ""


@dataclass
class ChainGraph:
    nodes: list[ChainNode] = field(default_factory=list)
    edges: list[ChainEdge] = field(default_factory=list)


@dataclass
class DangerousFunction:
    id: str
    file_path: str
    line_start: int
    function_name: str
    dangerous_api: str
    category: str
    snippet: str
    language: str = ""
    kind: str = "dangerous_api"
    rule_id: str = ""
    confidence: float = 0.5
    source: str = ""
    sink: str = ""
    evidence: list[str] = field(default_factory=list)
    tool_run_refs: list[str] = field(default_factory=list)
    artifact_refs: list[str] = field(default_factory=list)
    tool: str = "dangerous-function-locator"


@dataclass
class ProgramSlice:
    id: str
    dangerous_function_id: str
    file_path: str
    line_start: int
    function_name: str
    source: str
    sink: str
    controls: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    sink_args: list[str] = field(default_factory=list)
    definitions: list[str] = field(default_factory=list)
    call_chain: list[str] = field(default_factory=list)
    data_flow: list[str] = field(default_factory=list)
    guards: list[str] = field(default_factory=list)
    missing_guards: list[str] = field(default_factory=list)
    sanitizers: list[str] = field(default_factory=list)
    tool_evidence_ids: list[str] = field(default_factory=list)
    tool_run_refs: list[str] = field(default_factory=list)
    artifact_refs: list[str] = field(default_factory=list)
    context: str = ""
    code_excerpt: str = ""
    llm_summary: str = ""


@dataclass
class VulnerabilityCandidate:
    id: str
    slice_id: str
    title: str
    vulnerability_type: str
    severity: str
    file_path: str
    line_start: int
    description: str
    function_name: str = ""
    trigger_conditions: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    cwe: str = ""
    sink: str = ""
    source: str = ""
    missing_checks: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    confidence: float = 0.5
    valid: bool = True
    validity: str = "valid"
    llm_reasoning: str = ""


@dataclass
class Finding:
    id: str
    vulnerability_type: str
    severity: str
    title: str
    description: str
    file_path: str
    line_start: int | None = None
    line_end: int | None = None
    code_snippet: str = ""
    source: str = ""
    sink: str = ""
    call_chain: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    confidence: float = 0.5
    needs_verification: bool = True
    verification_status: str = "not_verified"
    evidence_strength: str = "weak"
    reachability: str = ""
    exploitability: str = ""
    should_verify: bool = True
    verification_reason: str = ""
    tool: str = "builtin"
    recommendation: str = ""
    route: str = ""
    exploit_payloads: list[str] = field(default_factory=list)
    exploit_chain: list[str] = field(default_factory=list)
    cwe: str = ""
    owasp: str = ""
    function_name: str = ""
    trigger_conditions: list[str] = field(default_factory=list)
    slice_id: str = ""
    candidate_id: str = ""
    dangerous_function_id: str = ""
    tool_run_refs: list[str] = field(default_factory=list)
    artifact_refs: list[str] = field(default_factory=list)
    chain_graph: ChainGraph = field(default_factory=ChainGraph)
    chinese_summary: str = ""


@dataclass
class VerificationResult:
    finding_id: str
    status: str
    method: str
    evidence: list[str] = field(default_factory=list)
    reproduction: str = ""
    poc_path: str = ""
    payloads: list[str] = field(default_factory=list)
    http_status: int | None = None
    http_evidence: str = ""
    analysis_verdict: str = ""
    rejection_reason: str = ""
    verification_mode: str = ""
    oracle: str = ""
    target_command: list[str] = field(default_factory=list)
    checker_status: str = ""
    checker_summary: str = ""
    exit_code: int | None = None
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""
    generated_artifacts: list[str] = field(default_factory=list)
    verification_method: str = ""
    verification_plan: dict[str, Any] = field(default_factory=dict)
    runtime_type: str = ""
    strategy: str = ""
    environment: dict[str, Any] = field(default_factory=dict)
    environment_gaps: list[str] = field(default_factory=list)
    execution: dict[str, Any] = field(default_factory=dict)
    evidence_artifact_ids: list[str] = field(default_factory=list)
    exploit_artifact_ids: list[str] = field(default_factory=list)
    checker_details: dict[str, Any] = field(default_factory=dict)
    local_fallback: bool = False
    entry_point: str = ""
    trigger_type: str = ""
    attempts: int = 0
    sandbox_command: list[str] = field(default_factory=list)
    sandbox_stdout: str = ""
    sandbox_stderr: str = ""
    artifact_ids: list[str] = field(default_factory=list)
    artifact_records: list[ArtifactRecord] = field(default_factory=list)


@dataclass
class VerificationAttemptRecord:
    task_id: str
    finding_id: str
    strategy: str = ""
    plan: dict[str, Any] = field(default_factory=dict)
    commands: list[list[str]] = field(default_factory=list)
    scripts_artifact_ids: list[str] = field(default_factory=list)
    exit_code: int | None = None
    stdout_artifact_id: str = ""
    stderr_artifact_id: str = ""
    generated_files: list[str] = field(default_factory=list)
    duration_ms: int | None = None
    checker_verdict: str = ""
    checker_reason: str = ""
    environment: dict[str, Any] = field(default_factory=dict)
    environment_gaps: list[str] = field(default_factory=list)
    execution: dict[str, Any] = field(default_factory=dict)
    evidence_artifact_ids: list[str] = field(default_factory=list)
    exploit_artifact_ids: list[str] = field(default_factory=list)
    checker_details: dict[str, Any] = field(default_factory=dict)
    local_fallback: bool = False
    data: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now)


@dataclass
class AuditReport:
    input_source: InputSource
    target: str
    created_at: str
    profile: ProjectProfile
    semantic_index: SemanticIndex
    tool_results: list[ToolResult]
    dangerous_functions: list[DangerousFunction]
    program_slices: list[ProgramSlice]
    candidates: list[VulnerabilityCandidate]
    findings: list[Finding]
    verification_results: list[VerificationResult]
    agent_events: list[AgentEvent] = field(default_factory=list)
    llm_enabled: bool = False
    llm_required: bool = True
    llm_provider: str = "deepseek"
    llm_model: str = "deepseek-v4-pro"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def normalize_path(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve())).replace("\\", "/")
    except ValueError:
        return str(path)
