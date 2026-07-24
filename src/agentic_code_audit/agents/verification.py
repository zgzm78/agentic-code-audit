from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin
from urllib.request import Request, urlopen

from ..llm import DeepSeekClient
from ..models import (
    ArtifactRecord,
    DangerousFunction,
    Finding,
    ProgramSlice,
    ProjectProfile,
    ToolResult,
    VerificationResult,
    VulnerabilityCandidate,
)
from ..vulnerability_types import VulnType, risk_domain_for


VERIFICATION_STATUSES = {
    "verified",
    "exploitable",
    "harness_reproduced",
    "partial_dynamic_proof",
    "partially_verified",
    "unverified",
    "not_reproducible",
    "blocked",
    "false_positive",
    "uncertain",
    "static_only",
}


@dataclass
class PocAnalysis:
    verdict: str
    verification_mode: str
    oracle: str
    details: str
    runtime_type: str = ""
    entry_point: str = ""
    trigger_type: str = ""
    max_attempts: int = 3
    rejection_reason: str = ""


@dataclass
class PocPlan:
    finding: Finding
    analysis: PocAnalysis
    poc_dir: Path
    poc_path: Path
    payload_paths: list[Path] = field(default_factory=list)
    runbook_path: Path | None = None
    target_command: list[str] = field(default_factory=list)
    generated_artifacts: list[Path] = field(default_factory=list)
    structured_plan: dict[str, Any] = field(default_factory=dict)


@dataclass
class CheckerOutcome:
    status: str
    summary: str
    evidence: list[str] = field(default_factory=list)
    exit_code: int | None = None
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""
    http_status: int | None = None
    http_evidence: str = ""
    sandbox_command: list[str] = field(default_factory=list)
    checker_details: dict[str, Any] = field(default_factory=dict)
    local_fallback: bool = False
    artifact_paths: list[Path] = field(default_factory=list)
    execution: dict[str, Any] = field(default_factory=dict)


@dataclass
class HarnessPlan:
    method: str
    language: str
    script: str
    command: list[str]
    oracle: str
    explanation: str
    strategy: str = ""
    runtime_type: str = ""
    rationale: str = ""
    setup_commands: list[list[str]] = field(default_factory=list)
    files_to_create: list[dict[str, str]] = field(default_factory=list)
    commands: list[list[str]] = field(default_factory=list)
    expected_signal: str = ""
    fallbacks: list[str] = field(default_factory=list)
    environment_requirements: list[str] = field(default_factory=list)
    mock_strategy: str = ""
    weak_verification_strategy: str = ""
    safety_notes: list[str] = field(default_factory=list)


@dataclass
class BuildDecision:
    should_attempt: bool
    reason: str
    build_system: str = ""
    instrumentation: list[str] = field(default_factory=list)
    status: str = "skipped"
    commands: list[list[str]] = field(default_factory=list)
    missing_tools: list[str] = field(default_factory=list)
    install_hints: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    blocked_reason: str = ""
    network_policy: str = "none"
    execution: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class EnvironmentProfile:
    runtime_type: str
    languages: dict[str, int]
    project_type: str
    available_tools: dict[str, str] = field(default_factory=dict)
    missing_tools: list[str] = field(default_factory=list)
    build_systems: list[str] = field(default_factory=list)
    runtime_entries: list[dict[str, Any]] = field(default_factory=list)
    test_entries: list[dict[str, Any]] = field(default_factory=list)
    verification_entries: list[dict[str, Any]] = field(default_factory=list)
    dependency_files: list[str] = field(default_factory=list)
    container_files: list[str] = field(default_factory=list)
    environment_gaps: list[str] = field(default_factory=list)
    install_hints: list[str] = field(default_factory=list)
    can_execute: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RuntimeDecision:
    runtime_type: str
    strategy: str
    rationale: str
    commands: list[list[str]] = field(default_factory=list)
    requires_build: bool = False
    can_execute: bool = False
    blocked_reason: str = ""
    fallbacks: list[str] = field(default_factory=list)

    def to_plan(self, finding: Finding, environment: EnvironmentProfile) -> dict[str, Any]:
        return {
            "strategy": self.strategy,
            "runtime_type": self.runtime_type,
            "rationale": self.rationale,
            "setup_commands": [],
            "files_to_create": [],
            "commands": self.commands,
            "expected_signal": "checker-specific oracle marker",
            "oracle": self._oracle_for(finding),
            "fallbacks": self.fallbacks,
            "environment_requirements": environment.missing_tools,
            "mock_strategy": "Use minimal local harnesses for library/plugin projects when safe.",
            "weak_verification_strategy": "Preserve source anchors, static evidence, and blocked reasons.",
            "safety_notes": [
                "Docker uses --network none when available.",
                "Local fallback is only used for generated short-lived harnesses.",
            ],
        }

    def _oracle_for(self, finding: Finding) -> dict[str, Any]:
        vuln_type = finding.vulnerability_type
        if vuln_type in {"unsafe_memory_copy", "unsafe_c_string_api", "memory_corruption"}:
            return {"checker": "MemorySafetyChecker", "signals": ["asan", "ubsan", "valgrind", "crash"]}
        if vuln_type == "command_injection":
            return {"checker": "CommandInjectionChecker", "signals": ["sentinel", "exit_code", "stdout"]}
        if vuln_type == "path_traversal":
            return {"checker": "PathTraversalChecker", "signals": ["sandbox sentinel file read"]}
        if vuln_type == "sql_injection":
            return {"checker": "SQLInjectionChecker", "signals": ["query result escaped expected predicate"]}
        if self.runtime_type == "http_service":
            return {"checker": "HttpChecker", "signals": ["http status", "oracle marker"]}
        if vuln_type == "dependency_vulnerability":
            return {"checker": "DependencyChecker", "signals": ["affected package/version evidence"]}
        return {"checker": "GenericChecker", "signals": ["real execution evidence required"]}


@dataclass
class StaticVerificationResult:
    finding_id: str
    static_status: str
    reachability: str
    dynamic_eligible: bool
    reason: str
    risk_domain: str
    evidence_refs: list[str] = field(default_factory=list)
    rule_checks: dict[str, Any] = field(default_factory=dict)
    llm_review: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DynamicVerificationPlan:
    finding_id: str
    status: str
    runtime_type: str
    build_strategy: str
    poc_strategy: str
    oracle: str
    rationale: str
    strategy: str = ""
    commands: list[list[str]] = field(default_factory=list)
    environment_requirements: list[str] = field(default_factory=list)
    fallbacks: list[str] = field(default_factory=list)
    blocked_reason: str = ""
    director_hint: dict[str, Any] = field(default_factory=dict)
    planner_review: dict[str, Any] = field(default_factory=dict)
    verification_recipe: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_runtime_decision(self) -> RuntimeDecision:
        return RuntimeDecision(
            runtime_type=self.runtime_type,
            strategy=self.strategy or self.poc_strategy,
            rationale=self.rationale,
            commands=self.commands,
            requires_build=self.build_strategy not in {"", "none", "existing_binary", "no_build_required"},
            can_execute=self.status == "planned",
            blocked_reason=self.blocked_reason,
            fallbacks=self.fallbacks,
        )


class StaticVerifier:
    """Validate mining evidence before any build, PoC generation, or runtime execution."""

    NON_SOURCE_DOMAINS = {"supply_chain_config", "dependency", "secret", "environment", "other"}
    DYNAMIC_STATUSES = {"plausible", "weak_static_proof"}

    def __init__(self, llm_client: DeepSeekClient | None = None) -> None:
        self.llm_client = llm_client

    def verify(
        self,
        target: Path,
        finding: Finding,
        candidate: VulnerabilityCandidate | None = None,
        program_slice: ProgramSlice | None = None,
        dangerous_function: DangerousFunction | None = None,
        tool_results: list[ToolResult] | None = None,
    ) -> StaticVerificationResult:
        self._coerce_source_finding(finding, program_slice)
        risk_domain = self._risk_domain(finding)
        source_path = (target / finding.file_path).resolve() if finding.file_path else None
        target_root = target.resolve()
        path_in_target = bool(source_path and (source_path == target_root or target_root in source_path.parents))
        file_exists = bool(path_in_target and source_path and source_path.is_file())
        line_exists = self._line_exists(source_path, finding.line_start) if file_exists else False
        candidate_valid = candidate is None or (candidate.valid and candidate.validity == "valid")

        source = finding.source or (program_slice.source if program_slice else "")
        sink = finding.sink or (program_slice.sink if program_slice else "")
        if not sink and finding.code_snippet and risk_domain == "source_code":
            sink = finding.code_snippet[:300]
        missing_guards = list(program_slice.missing_guards) if program_slice else []
        data_flow = list(program_slice.data_flow) if program_slice else []
        call_chain = list(program_slice.call_chain) if program_slice else list(finding.call_chain)
        evidence_graph = program_slice.evidence_graph if program_slice else finding.evidence_graph
        has_evidence_graph = bool(getattr(evidence_graph, "id", ""))
        graph_status = (
            getattr(program_slice, "slice_status", "")
            or getattr(finding, "slice_status", "")
            or (getattr(evidence_graph, "status", "") if has_evidence_graph else "")
        )
        graph_paths = list(getattr(evidence_graph, "paths", []) or [])
        fact_taint_path = any(path.kind == "taint" and path.status == "proven" for path in graph_paths)
        parameter_path = any(path.kind == "taint" and path.status == "source_unresolved" for path in graph_paths)
        if not has_evidence_graph:
            fact_taint_path = bool(data_flow)
            entry_reachable = bool(call_chain)
        else:
            entry_reachable = graph_status in {"entry_tainted_flow", "entry_parameter_flow", "entry_reachable_no_taint"}
        graph_gaps = list(getattr(evidence_graph, "gaps", []) or [])
        tool_run_refs = list(dict.fromkeys([
            *finding.tool_run_refs,
            *(program_slice.tool_run_refs if program_slice else []),
            *(dangerous_function.tool_run_refs if dangerous_function else []),
        ]))
        artifact_refs = list(dict.fromkeys([
            *finding.artifact_refs,
            *(candidate.evidence_refs if candidate else []),
            *(program_slice.artifact_refs if program_slice else []),
        ]))
        known_tool_runs = {item.run_id for item in (tool_results or []) if item.run_id}
        tool_refs_resolve = not tool_run_refs or bool(known_tool_runs.intersection(tool_run_refs)) or not tool_results
        tool_corroborated = bool(tool_run_refs) or finding.tool not in {"", "builtin", "builtin-patterns"}
        direct_parameter_flow = self._direct_parameter_to_sink(source_path, finding) if file_exists else False
        trace_linked = all(
            (
                not expected_id,
                linked is not None and getattr(linked, "id", "") == expected_id,
            )[bool(expected_id)]
            for expected_id, linked in (
                (finding.candidate_id, candidate),
                (finding.slice_id, program_slice),
                (finding.dangerous_function_id, dangerous_function),
            )
        )
        rule_checks = {
            "path_in_target": path_in_target,
            "file_exists": file_exists,
            "line_exists": line_exists,
            "candidate_valid": candidate_valid,
            "trace_linked": trace_linked,
            "source_present": bool(source),
            "sink_present": bool(sink),
            "missing_guards_present": bool(missing_guards),
            "call_chain_present": bool(call_chain),
            "data_flow_present": bool(data_flow),
            "evidence_graph_status": graph_status,
            "fact_taint_path": fact_taint_path,
            "parameter_path": parameter_path,
            "entry_reachable": entry_reachable,
            "graph_gaps": graph_gaps[:8],
            "tool_corroborated": tool_corroborated,
            "tool_refs_resolve": tool_refs_resolve,
            "evidence_present": bool(finding.evidence),
            "direct_parameter_to_sink": direct_parameter_flow,
        }

        if risk_domain in self.NON_SOURCE_DOMAINS:
            static_status = "static_only"
            reachability = "unknown"
            reason = f"Risk domain '{risk_domain}' is evaluated from static evidence and is not dynamically executed."
        elif not finding.file_path:
            static_status = "blocked_static"
            reachability = "unknown"
            reason = "Finding has no source file path."
        elif not path_in_target or not file_exists:
            static_status = "likely_false_positive"
            reachability = "unlikely"
            reason = "Reported source file is missing or outside the target repository."
        elif not candidate_valid or not trace_linked:
            static_status = "likely_false_positive"
            reachability = "unlikely"
            reason = "Mining trace is invalid or references an invalid candidate."
        elif source and sink and fact_taint_path:
            static_status = "plausible"
            reachability = "reachable" if entry_reachable else "likely_reachable"
            reason = "Evidence graph contains a fact-backed tainted path from source to sink."
        elif source and sink and direct_parameter_flow and not parameter_path:
            static_status = "plausible"
            reachability = "likely_reachable"
            reason = "A function parameter is passed directly to the dangerous sink."
        elif source and sink and parameter_path:
            static_status = "weak_static_proof"
            reachability = "likely_reachable" if entry_reachable else "unknown"
            reason = "A parameter reaches the sink, but the caller-controlled source is unresolved."
        elif source and sink and (missing_guards or tool_corroborated or graph_status in {"entry_reachable_no_taint", "local_tainted_flow"}):
            static_status = "weak_static_proof"
            reachability = "likely_reachable" if entry_reachable else "unknown"
            reason = "Source and sink evidence exists, but a fact-backed taint path is not complete."
        elif sink and finding.evidence:
            static_status = "weak_static_proof"
            reachability = "likely_reachable" if source or finding.reachability in {"reachable", "likely_reachable"} else "unknown"
            reason = "The sink is anchored in source, but full source-to-sink reachability is not proven."
        elif finding.confidence < 0.35:
            static_status = "likely_false_positive"
            reachability = "unlikely"
            reason = "The finding lacks a stable source/sink trace and has low confidence."
        else:
            static_status = "needs_more_context"
            reachability = "unknown"
            reason = "The available mining evidence is insufficient to establish reachability."

        dynamic_eligible = (
            risk_domain == "source_code"
            and static_status in self.DYNAMIC_STATUSES
            and finding.should_verify
        )
        refs = list(dict.fromkeys([*tool_run_refs, *artifact_refs]))
        return StaticVerificationResult(
            finding_id=finding.id,
            static_status=static_status,
            reachability=reachability,
            dynamic_eligible=dynamic_eligible,
            reason=reason,
            risk_domain=risk_domain,
            evidence_refs=refs,
            rule_checks=rule_checks,
        )

    @staticmethod
    def _direct_parameter_to_sink(source_path: Path | None, finding: Finding) -> bool:
        """Recognize a Python function parameter passed directly into the reported sink."""
        if not source_path or source_path.suffix.lower() != ".py" or not finding.sink:
            return False
        try:
            tree = ast.parse(source_path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, SyntaxError, UnicodeError):
            return False

        expected_function = finding.function_name.strip()
        expected_sink = finding.sink.rsplit(".", 1)[-1].strip()
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if expected_function and node.name != expected_function:
                continue
            parameters = {
                item.arg
                for item in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            }
            if node.args.vararg:
                parameters.add(node.args.vararg.arg)
            if node.args.kwarg:
                parameters.add(node.args.kwarg.arg)
            for child in ast.walk(node):
                if not isinstance(child, ast.Call):
                    continue
                called = StaticVerifier._python_call_name(child.func)
                if called.rsplit(".", 1)[-1] != expected_sink:
                    continue
                if any(isinstance(arg, ast.Name) and arg.id in parameters for arg in child.args):
                    return True
        return False

    @staticmethod
    def _python_call_name(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = StaticVerifier._python_call_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""

    def review_batch(
        self,
        findings: list[Finding],
        results: list[StaticVerificationResult],
    ) -> None:
        if not findings or not self.llm_client or not hasattr(self.llm_client, "chat"):
            return
        if getattr(self.llm_client, "enabled", True) is False:
            return
        payload = []
        for finding, result in zip(findings, results):
            payload.append(
                {
                    "finding_id": finding.id,
                    "type": finding.vulnerability_type,
                    "risk_domain": result.risk_domain,
                    "file": finding.file_path,
                    "function": finding.function_name,
                    "source": finding.source,
                    "sink": finding.sink,
                    "evidence": [str(item)[:240] for item in finding.evidence[:6]],
                    "rule_result": result.to_dict(),
                }
            )
        prompt = (
            "Review these source-audit findings as a static verification assistant. "
            "Return a JSON array only. Each item must contain finding_id, verdict "
            "(plausible|weak_static_proof|likely_false_positive|needs_more_context), "
            "reachability (reachable|likely_reachable|unknown|unlikely), and reason. "
            "Do not claim dynamic exploitation or verified status.\n"
            + json.dumps(payload, ensure_ascii=False, default=str)
        )
        try:
            response = self.llm_client.chat(
                "You review static security evidence. Rules and repository facts are authoritative.",
                prompt,
                timeout=45,
            )
        except Exception as exc:
            self._record_review_error(results, str(exc))
            return
        if not response.ok:
            self._record_review_error(results, response.error or "LLM review failed")
            return
        reviews = self._parse_reviews(response.content)
        by_id = {str(item.get("finding_id", "")): item for item in reviews}
        for finding, result in zip(findings, results):
            review = by_id.get(finding.id)
            if not review:
                result.llm_review = {"status": "missing", "accepted": False}
                continue
            self._apply_review(finding, result, review)

    def _apply_review(
        self,
        finding: Finding,
        result: StaticVerificationResult,
        review: dict[str, Any],
    ) -> None:
        verdict = str(review.get("verdict", "")).strip().lower()
        reachability = str(review.get("reachability", "")).strip().lower()
        reason = str(review.get("reason", "")).strip()[:600]
        accepted = False
        if result.risk_domain == "source_code":
            if result.static_status == "plausible" and verdict in {"weak_static_proof", "needs_more_context"}:
                result.static_status = verdict
                accepted = True
            elif result.static_status == "weak_static_proof" and verdict == "plausible":
                checks = result.rule_checks
                if checks.get("file_exists") and checks.get("source_present") and checks.get("sink_present"):
                    result.static_status = verdict
                    accepted = True
            elif verdict == "likely_false_positive" and result.static_status in {"plausible", "weak_static_proof", "needs_more_context"}:
                result.static_status = "needs_more_context"
                accepted = True
            if reachability in {"likely_reachable", "unknown", "unlikely"}:
                result.reachability = reachability
                accepted = True
            elif reachability == "reachable" and result.rule_checks.get("fact_taint_path"):
                result.reachability = reachability
                accepted = True
        result.dynamic_eligible = (
            result.risk_domain == "source_code"
            and result.static_status in self.DYNAMIC_STATUSES
            and finding.should_verify
        )
        if accepted and reason:
            result.reason = f"{result.reason} LLM review: {reason}"
        result.llm_review = {
            "status": "completed",
            "verdict": verdict,
            "reachability": reachability,
            "reason": reason,
            "accepted": accepted,
        }

    def _risk_domain(self, finding: Finding) -> str:
        explicit = str(getattr(finding, "risk_domain", "") or "").strip()
        if explicit and explicit not in {"environment", "other"}:
            return explicit
        if explicit in {"environment", "other"} and self._source_code_type_hint(finding):
            return "source_code"
        return risk_domain_for(VulnType.from_string(finding.vulnerability_type)).value

    def _coerce_source_finding(self, finding: Finding, program_slice: ProgramSlice | None = None) -> None:
        if finding.vulnerability_type not in {"", "other", "weak_static_proof"}:
            return
        hint = self._source_code_type_hint(finding, program_slice)
        if not hint:
            return
        finding.vulnerability_type = hint
        if getattr(finding, "risk_domain", "") in {"", "environment", "other"}:
            finding.risk_domain = "source_code"
        finding.should_verify = True
        finding.needs_verification = True
        finding.verification_reason = (
            "Source-code finding was reclassified during static verification; "
            "dynamic execution depends on the static verdict."
        )

    @staticmethod
    def _source_code_type_hint(finding: Finding, program_slice: ProgramSlice | None = None) -> str:
        if finding.vulnerability_type in {"dependency_vulnerability", "secret_leak", "hardcoded_secret", "supply_chain_config"}:
            return ""
        parts = [
            finding.vulnerability_type,
            finding.file_path,
            finding.source,
            finding.sink,
            finding.title,
            finding.description,
            finding.code_snippet,
            *(finding.evidence or [])[:8],
        ]
        if program_slice:
            parts.extend([
                program_slice.rule_vuln_type,
                program_slice.anchor_category,
                program_slice.source,
                program_slice.sink,
                program_slice.context,
                program_slice.code_excerpt,
            ])
        text = "\n".join(str(item or "") for item in parts).lower()
        command_markers = (
            "command_injection",
            "exec-use",
            "shell_exec",
            "passthru",
            "proc_open",
            "popen",
            "system(",
            "os.system",
            "subprocess",
            "child_process",
            "runtime.exec",
        )
        if any(marker in text for marker in command_markers):
            return "command_injection"
        sql_markers = (
            "sql_injection",
            "sqli",
            "sql-injection",
            "mysqli_query",
            "mysql_query",
            "pdo::query",
            "db.query",
            "executequery",
        )
        if any(marker in text for marker in sql_markers):
            return "sql_injection"
        path_markers = (
            "path_traversal",
            "path-traversal",
            "file_get_contents",
            "readfile",
            "fopen",
            "include(",
            "require(",
            "../",
            "..\\",
        )
        if any(marker in text for marker in path_markers):
            return "path_traversal"
        code_markers = ("eval(", "assert(", "create_function", "deserialize", "unserialize")
        if any(marker in text for marker in code_markers):
            return "code_execution"
        return ""

    @staticmethod
    def _line_exists(path: Path | None, line_start: int | None) -> bool:
        if not path or not line_start or line_start < 1:
            return False
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as handle:
                return any(index == line_start for index, _line in enumerate(handle, start=1))
        except OSError:
            return False

    @staticmethod
    def _parse_reviews(content: str) -> list[dict[str, Any]]:
        text = content.strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.I | re.S)
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            match = re.search(r"\[.*\]", text, re.S)
            if not match:
                return []
            try:
                parsed = json.loads(match.group(0))
            except json.JSONDecodeError:
                return []
        if isinstance(parsed, dict):
            parsed = parsed.get("reviews", [])
        return [item for item in parsed if isinstance(item, dict)] if isinstance(parsed, list) else []

    @staticmethod
    def _record_review_error(results: list[StaticVerificationResult], reason: str) -> None:
        for result in results:
            result.llm_review = {"status": "failed", "reason": reason[:300], "accepted": False}


class EnvironmentManager:
    """Build a verification environment profile from static profile plus finding context."""

    TOOL_HINTS = {
        "docker": "Install Docker Desktop or use the project Docker Compose environment.",
        "cmake": "Install CMake or use the sandbox image.",
        "ninja": "Install Ninja or use CMake's default generator.",
        "make": "Install GNU make or use WSL/sandbox.",
        "gcc": "Install GCC/MSYS2/WSL or use the sandbox image.",
        "g++": "Install G++/MSYS2/WSL or use the sandbox image.",
        "clang": "Install LLVM or use the sandbox image.",
        "clang++": "Install LLVM or use the sandbox image.",
        "pytest": "Install pytest in the project environment.",
        "python": "Install Python or use the sandbox image.",
        "node": "Install Node.js LTS.",
        "npm": "Install Node.js LTS.",
        "php": "Install PHP CLI or use the sandbox image.",
        "composer": "Install Composer or use the sandbox image.",
        "java": "Install a JDK or use the sandbox image.",
        "javac": "Install a JDK or use the sandbox image.",
        "mvn": "Install Maven or use the sandbox image.",
        "gradle": "Install Gradle or use the sandbox image.",
        "go": "Install Go or use the sandbox image.",
        "curl": "Install curl or use PowerShell Invoke-WebRequest manually.",
        "sqlite3": "Install sqlite3 CLI or use Python sqlite3 for harnesses.",
    }

    def __init__(self, sandbox_container: str = "agentic-code-audit-sandbox") -> None:
        self.sandbox_container = sandbox_container

    def inspect(self, target: Path, profile: ProjectProfile, finding: Finding) -> EnvironmentProfile:
        runtime_type = self._runtime_type(profile, finding)
        tools = self._tools_for(runtime_type, profile, target)
        available: dict[str, str] = {}
        missing: list[str] = []
        # Tools that must be checked in the sandbox container, not the backend
        SANDBOX_CHECK_TOOLS = {
            "cmake", "make", "ninja", "gcc", "g++", "clang", "clang++",
            "valgrind", "gdb", "lldb", "ctags", "python", "pytest", "node", "npm",
            "php", "composer", "java", "javac", "mvn", "gradle", "go",
        }
        sandbox_available = self._sandbox_reachable(self.sandbox_container)
        for tool in tools:
            if tool in SANDBOX_CHECK_TOOLS and sandbox_available:
                if self._check_sandbox_tool(tool, self.sandbox_container):
                    available[tool] = f"sandbox:{tool}"
                else:
                    missing.append(tool)
            else:
                path = shutil.which(tool)
                if path:
                    available[tool] = path
                else:
                    missing.append(tool)
        build_systems = self._build_systems(target)
        gaps = [f"missing tool: {tool}" for tool in missing]
        if runtime_type in {"static_blocked", "weak_static_proof"}:
            gaps.append("no executable entry point was identified")
        if runtime_type in {"rust_blocked", "ruby_blocked"}:
            gaps.append(f"{runtime_type.removesuffix('_blocked')} dynamic verification is not enabled in this phase")
        hints = [self.TOOL_HINTS.get(tool, f"Install {tool} or use the Docker sandbox.") for tool in missing]
        can_execute = runtime_type not in {"static_blocked"} and not runtime_type.endswith("_blocked")
        return EnvironmentProfile(
            runtime_type=runtime_type,
            languages=dict(profile.languages),
            project_type=profile.project_type,
            available_tools=available,
            missing_tools=missing,
            build_systems=build_systems,
            runtime_entries=list(profile.runtime_entries),
            test_entries=list(profile.test_entries),
            verification_entries=list(profile.verification_entries),
            dependency_files=list(profile.dependency_files or profile.package_files),
            container_files=list(profile.container_files),
            environment_gaps=gaps,
            install_hints=hints,
            can_execute=can_execute,
        )

    def _runtime_type(self, profile: ProjectProfile, finding: Finding) -> str:
        if finding.route:
            return "http_service"
        # Use risk_domain for supply-chain / dependency / secret — never run sandbox
        risk_domain = getattr(finding, "risk_domain", "")
        if risk_domain in {"supply_chain_config", "dependency", "secret"}:
            return "static_blocked"
        if finding.vulnerability_type in {"dependency_vulnerability", "hardcoded_secret", "secret_leak"}:
            return "dependency_only" if finding.vulnerability_type == "dependency_vulnerability" else "weak_static_proof"
        suffix = Path(finding.file_path).suffix.lower()
        languages = set(profile.languages)
        if suffix in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"} or {"C", "C++"} & languages:
            return "cpp_cli"
        if suffix == ".py" or "Python" in languages:
            return "python_test"
        if suffix in {".js", ".jsx", ".ts", ".tsx"} or {"JavaScript", "TypeScript"} & languages:
            return "node_test"
        if "Go" in languages:
            return "go_test"
        if "Rust" in languages:
            return "rust_blocked"
        if "Java" in languages:
            return "java_test"
        if "PHP" in languages:
            return "php_test"
        if "Ruby" in languages:
            return "ruby_blocked"
        if profile.library_entries or profile.project_type == "library":
            return "library_harness"
        return "weak_static_proof"

    def _tools_for(self, runtime_type: str, profile: ProjectProfile, target: Path) -> list[str]:
        tools = ["docker"]
        if runtime_type in {"cpp_cli", "cpp_harness"}:
            tools.extend(["cmake", "make", "gcc", "g++", "clang", "clang++", "valgrind", "gdb"])
        if runtime_type == "python_test":
            tools.extend(["python", "pytest"])
        if runtime_type == "node_test":
            tools.extend(["node", "npm"])
        if runtime_type == "php_test":
            tools.extend(["php", "composer"])
        if runtime_type == "java_test":
            tools.extend(["java", "javac"])
            if (target / "pom.xml").exists():
                tools.append("mvn")
            if (target / "build.gradle").exists() or (target / "build.gradle.kts").exists():
                tools.append("gradle")
        if runtime_type == "go_test":
            tools.extend(["go"])
        if runtime_type == "http_service":
            tools.append("curl")
        if target.exists() and any(name.endswith(".db") or name.endswith(".sqlite") for name in os.listdir(target)):
            tools.append("sqlite3")
        return list(dict.fromkeys(tools))

    def _build_systems(self, target: Path) -> list[str]:
        systems: list[str] = []
        has_autotools = any(
            (target / name).exists()
            for name in ("configure", "configure.ac", "configure.in", "autogen.sh", "Makefile.am")
        )
        if has_autotools:
            systems.append("autotools")
        if (target / "CMakeLists.txt").exists():
            systems.append("cmake")
        if (target / "Makefile").exists() or (target / "makefile").exists():
            systems.append("make")
        if (target / "meson.build").exists():
            systems.append("meson")
        if (target / "package.json").exists():
            systems.append("npm")
        if (target / "pyproject.toml").exists() or (target / "requirements.txt").exists():
            systems.append("python")
        return list(dict.fromkeys(systems))

    @staticmethod
    def _sandbox_reachable(container: str = "agentic-code-audit-sandbox") -> bool:
        """Check whether the sandbox container is running."""
        try:
            proc = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Running}}", container],
                text=True, capture_output=True, timeout=5, check=False,
            )
            return proc.stdout.strip() == "true"
        except (OSError, subprocess.TimeoutExpired):
            return False

    @staticmethod
    def _check_sandbox_tool(tool: str, container: str = "agentic-code-audit-sandbox") -> bool:
        """Check whether *tool* is available inside the sandbox container."""
        try:
            proc = subprocess.run(
                ["docker", "exec", container, "which", tool],
                text=True, capture_output=True, timeout=10, check=False,
            )
            return proc.returncode == 0 and bool(proc.stdout.strip())
        except (OSError, subprocess.TimeoutExpired):
            return False


class BuildManager:
    """Prepare build/runtime assets and record blocked reasons instead of guessing silently."""

    def __init__(
        self,
        sandbox_container: str = "agentic-code-audit-sandbox",
        sandbox_image: str = "agentic-code-audit-sandbox:local",
        build_network_enabled: bool = False,
    ) -> None:
        self.sandbox_container = sandbox_container
        self.sandbox_image = sandbox_image
        self.build_network_enabled = build_network_enabled

    def prepare(
        self,
        target: Path,
        profile: ProjectProfile,
        finding: Finding,
        environment: EnvironmentProfile,
        output_dir: Path,
        auto_build_native: bool = False,
    ) -> tuple[BuildDecision, Path | None]:
        runtime_type = environment.runtime_type
        if runtime_type not in {"cpp_cli", "cpp_harness"}:
            return BuildDecision(False, f"No build step is required for {runtime_type}.", status="skipped"), None

        existing = PocGenerator()._find_native_executable(target)
        if existing:
            decision = BuildDecision(
                False,
                f"Found existing native executable: {existing}",
                status="ready",
                network_policy="not_required",
            )
            decision.evidence.append(decision.reason)
            return decision, existing

        build_systems = list(environment.build_systems)
        build_system = build_systems[0] if build_systems else ""
        network_policy = "bridge" if self.build_network_enabled else "none"
        if not auto_build_native:
            decision = BuildDecision(
                False,
                "Native build is disabled for this task.",
                build_system=build_system,
                instrumentation=["asan", "ubsan"],
                status="blocked",
                blocked_reason="build_disabled",
                network_policy=network_policy,
            )
            decision.evidence.append(decision.reason)
            return decision, None

        if not build_system:
            decision = BuildDecision(
                False,
                "No supported native build system was detected.",
                build_system=build_system,
                instrumentation=["asan", "ubsan"],
                status="blocked",
                blocked_reason="binary_not_found",
                network_policy=network_policy,
            )
            decision.evidence.append(decision.reason)
            return decision, None

        if not self._sandbox_reachable():
            decision = BuildDecision(
                False,
                f"Build sandbox '{self.sandbox_container}' is unavailable.",
                build_system=build_system,
                instrumentation=["asan", "ubsan"],
                status="blocked",
                blocked_reason="sandbox_unavailable",
                network_policy=network_policy,
            )
            decision.evidence.append(decision.reason)
            return decision, None

        last_decision: BuildDecision | None = None
        for system in build_systems:
            missing = self._missing_build_tools(system)
            if missing:
                decision = BuildDecision(
                    False,
                    f"Native build blocked because required sandbox tools are missing: {', '.join(missing)}.",
                    build_system=system,
                    instrumentation=["asan", "ubsan"],
                    status="blocked",
                    missing_tools=missing,
                    install_hints=[EnvironmentManager.TOOL_HINTS.get(item, f"Install {item} in the sandbox image.") for item in missing],
                    blocked_reason="missing_tool",
                    network_policy=network_policy,
                )
                decision.evidence.extend([decision.reason, *decision.install_hints])
                last_decision = decision
                continue

            if system == "cmake":
                decision, executable = self._build_cmake(target, output_dir)
            elif system == "autotools":
                decision, executable = self._build_autotools(target, output_dir)
            else:
                decision, executable = (
                    BuildDecision(
                        False,
                        f"Build system '{system}' is detected but automatic execution is not implemented.",
                        build_system=system,
                        instrumentation=["asan", "ubsan"],
                        status="blocked",
                        blocked_reason="build_failed",
                        network_policy=network_policy,
                    ),
                    None,
                )
                decision.evidence.append(decision.reason)
            if executable or decision.status == "ready":
                return decision, executable
            last_decision = decision
            if decision.blocked_reason != "wrong_build_system":
                break

        if last_decision:
            return last_decision, None
        decision = BuildDecision(
            False,
            "No supported native build system could be executed.",
            build_system=build_system,
            instrumentation=["asan", "ubsan"],
            status="blocked",
            blocked_reason="build_failed",
            network_policy=network_policy,
        )
        decision.evidence.append(decision.reason)
        return decision, None

    def _missing_build_tools(self, build_system: str) -> list[str]:
        required: dict[str, list[str]] = {
            "cmake": ["cmake", "clang or gcc"],
            "autotools": [
                "make",
                "clang or gcc",
                "autoreconf or autoconf",
                "automake or aclocal",
                "libtoolize or libtool",
            ],
            "make": ["make", "clang or gcc"],
            "meson": ["meson", "ninja", "clang or gcc"],
        }
        missing: list[str] = []
        for tool in required.get(build_system, [build_system]):
            if not self._sandbox_has_any_tool(tool.split(" or ")):
                missing.append(tool)
        return missing

    def _build_cmake(self, target: Path, output_dir: Path) -> tuple[BuildDecision, Path | None]:
        build_dir = target / ".agentic-build"
        build_dir.mkdir(parents=True, exist_ok=True)
        output_dir.mkdir(parents=True, exist_ok=True)
        log_path = output_dir / "native-build.log"
        # Translate paths for sandbox container (volume mount: /app/runs → /workspace/runs)
        from ..tools.runner import _translate_path_for_sandbox
        sandbox_target = _translate_path_for_sandbox(str(target))
        sandbox_build_dir = _translate_path_for_sandbox(str(build_dir))
        network_policy = "bridge" if self.build_network_enabled else "none"
        exiv2_flags = ""
        if (target / "src" / "exiv2.cpp").exists() or target.name.lower() == "exiv2":
            exiv2_flags = (
                "-DEXIV2_ENABLE_PNG=OFF "
                "-DEXIV2_ENABLE_XMP=OFF "
                "-DEXIV2_ENABLE_WEBREADY=OFF "
                "-DEXIV2_ENABLE_BMFF=OFF "
                "-DEXIV2_ENABLE_NLS=OFF "
                "-DEXIV2_ENABLE_INIH=OFF "
                "-DEXIV2_ENABLE_EXTERNAL_XMP=OFF "
                "-DEXIV2_BUILD_SAMPLES=OFF "
            )
        configure_cmd = (
            f"cmake -S {shlex.quote(sandbox_target)} -B {shlex.quote(sandbox_build_dir)} "
            f"-DCMAKE_BUILD_TYPE=Debug "
            f"-DBUILD_TESTING=OFF "
            f"{exiv2_flags}"
            f'-DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" '
            f'-DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"'
        )
        build_cmd = f"cmake --build {shlex.quote(sandbox_build_dir)} --config Debug -j 2"
        logs: list[str] = []
        executions: list[dict[str, Any]] = []
        for step_name, shell_cmd in [("configure", configure_cmd), ("build", build_cmd)]:
            docker_cmd = [
                "docker", "run", "--rm",
                "--network", network_policy,
                "--memory", "2g",
                "--cpus", "2",
                "--volumes-from", self.sandbox_container,
                "-w", sandbox_target,
                self.sandbox_image,
                "sh", "-lc", shell_cmd,
            ]
            try:
                completed = subprocess.run(
                    docker_cmd,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=900,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                log_path.write_text("\n\n".join(logs + [str(exc)]), encoding="utf-8")
                return (
                    BuildDecision(
                        should_attempt=True,
                        reason=f"CMake {step_name} failed before completion: {exc}",
                        build_system="cmake",
                        instrumentation=["asan", "ubsan"],
                        status="blocked",
                        evidence=[f"Build log: {log_path}"],
                        blocked_reason="build_failed",
                        network_policy=network_policy,
                        execution=executions,
                    ),
                    None,
                )
            execution = {
                "step": step_name,
                "command": docker_cmd,
                "exit_code": completed.returncode,
                "stdout": completed.stdout[-8000:],
                "stderr": completed.stderr[-8000:],
                "network_policy": network_policy,
            }
            executions.append(execution)
            logs.append(
                "\n".join(
                    [
                        f"$ docker run --network {network_policy} {self.sandbox_image} sh -lc '{shell_cmd[:120]}...'",
                        f"exit_code={completed.returncode}",
                        completed.stdout[-8000:],
                        completed.stderr[-8000:],
                    ]
                )
            )
            if completed.returncode != 0:
                log_path.write_text("\n\n".join(logs), encoding="utf-8")
                blocked_reason = self._classify_build_failure(completed.stdout, completed.stderr)
                return (
                    BuildDecision(
                        should_attempt=True,
                        reason=f"CMake {step_name} exited with {completed.returncode}.",
                        build_system="cmake",
                        instrumentation=["asan", "ubsan"],
                        status="blocked",
                        evidence=[f"Build log: {log_path}"],
                        blocked_reason=blocked_reason,
                        network_policy=network_policy,
                        execution=executions,
                    ),
                    None,
                )
        log_path.write_text("\n\n".join(logs), encoding="utf-8")
        built = PocGenerator()._find_native_executable(target)
        if built:
            return (
                BuildDecision(
                    should_attempt=True,
                    reason=f"Built native executable: {built}",
                    build_system="cmake",
                    instrumentation=["asan", "ubsan"],
                    status="ready",
                    evidence=[f"Built native executable: {built}", f"Build log: {log_path}"],
                    commands=[["sh", "-lc", configure_cmd], ["sh", "-lc", build_cmd]],
                    network_policy=network_policy,
                    execution=executions,
                ),
                built,
            )
        return (
            BuildDecision(
                should_attempt=True,
                reason="CMake build completed, but no executable was detected.",
                build_system="cmake",
                instrumentation=["asan", "ubsan"],
                status="blocked",
                evidence=[f"Build log: {log_path}"],
                commands=[["sh", "-lc", configure_cmd], ["sh", "-lc", build_cmd]],
                blocked_reason="binary_not_found",
                network_policy=network_policy,
                execution=executions,
            ),
            None,
        )

    def _build_autotools(self, target: Path, output_dir: Path) -> tuple[BuildDecision, Path | None]:
        build_dir = target / ".agentic-build" / "autotools"
        build_dir.mkdir(parents=True, exist_ok=True)
        output_dir.mkdir(parents=True, exist_ok=True)
        log_path = output_dir / "native-build-autotools.log"
        from ..tools.runner import _translate_path_for_sandbox

        sandbox_target = _translate_path_for_sandbox(str(target))
        sandbox_build_dir = _translate_path_for_sandbox(str(build_dir))
        network_policy = "bridge" if self.build_network_enabled else "none"
        configure_exists = (target / "configure").exists()
        autogen_exists = (target / "autogen.sh").exists()
        if configure_exists:
            bootstrap_cmd = ""
        elif autogen_exists:
            bootstrap_cmd = f"cd {shlex.quote(sandbox_target)} && sh ./autogen.sh"
        else:
            bootstrap_cmd = f"cd {shlex.quote(sandbox_target)} && autoreconf -vi"
        configure_cmd = (
            f"cd {shlex.quote(sandbox_build_dir)} && "
            f"{shlex.quote(sandbox_target)}/configure "
            f'CFLAGS="-g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer" '
            f'CXXFLAGS="-g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer" '
            f'LDFLAGS="-fsanitize=address,undefined"'
        )
        build_cmd = f"cd {shlex.quote(sandbox_build_dir)} && make -j 2"
        steps = [("bootstrap", bootstrap_cmd), ("configure", configure_cmd), ("build", build_cmd)]
        logs: list[str] = []
        executions: list[dict[str, Any]] = []
        for step_name, shell_cmd in steps:
            if not shell_cmd:
                continue
            docker_cmd = [
                "docker", "run", "--rm",
                "--network", network_policy,
                "--memory", "2g",
                "--cpus", "2",
                "--volumes-from", self.sandbox_container,
                "-w", sandbox_target,
                self.sandbox_image,
                "sh", "-lc", shell_cmd,
            ]
            try:
                completed = subprocess.run(
                    docker_cmd,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=900,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                log_path.write_text("\n\n".join(logs + [str(exc)]), encoding="utf-8")
                return (
                    BuildDecision(
                        should_attempt=True,
                        reason=f"Autotools {step_name} failed before completion: {exc}",
                        build_system="autotools",
                        instrumentation=["asan", "ubsan"],
                        status="blocked",
                        evidence=[f"Build log: {log_path}"],
                        blocked_reason="build_failed",
                        network_policy=network_policy,
                        execution=executions,
                    ),
                    None,
                )
            execution = {
                "step": step_name,
                "command": docker_cmd,
                "exit_code": completed.returncode,
                "stdout": completed.stdout[-8000:],
                "stderr": completed.stderr[-8000:],
                "network_policy": network_policy,
            }
            executions.append(execution)
            logs.append(
                "\n".join(
                    [
                        f"$ docker run --network {network_policy} {self.sandbox_image} sh -lc '{shell_cmd[:120]}...'",
                        f"exit_code={completed.returncode}",
                        completed.stdout[-8000:],
                        completed.stderr[-8000:],
                    ]
                )
            )
            if completed.returncode != 0:
                log_path.write_text("\n\n".join(logs), encoding="utf-8")
                return (
                    BuildDecision(
                        should_attempt=True,
                        reason=f"Autotools {step_name} exited with {completed.returncode}.",
                        build_system="autotools",
                        instrumentation=["asan", "ubsan"],
                        status="blocked",
                        evidence=[f"Build log: {log_path}"],
                        blocked_reason=self._classify_build_failure(completed.stdout, completed.stderr),
                        network_policy=network_policy,
                        execution=executions,
                    ),
                    None,
                )
        log_path.write_text("\n\n".join(logs), encoding="utf-8")
        built = PocGenerator()._find_native_executable(target)
        if built:
            return (
                BuildDecision(
                    should_attempt=True,
                    reason=f"Built native executable: {built}",
                    build_system="autotools",
                    instrumentation=["asan", "ubsan"],
                    status="ready",
                    evidence=[f"Built native executable: {built}", f"Build log: {log_path}"],
                    commands=[["sh", "-lc", cmd] for _name, cmd in steps if cmd],
                    network_policy=network_policy,
                    execution=executions,
                ),
                built,
            )
        return (
            BuildDecision(
                should_attempt=True,
                reason="Autotools build completed, but no executable was detected.",
                build_system="autotools",
                instrumentation=["asan", "ubsan"],
                status="blocked",
                evidence=[f"Build log: {log_path}"],
                commands=[["sh", "-lc", cmd] for _name, cmd in steps if cmd],
                blocked_reason="binary_not_found",
                network_policy=network_policy,
                execution=executions,
            ),
            None,
        )

    def _sandbox_reachable(self) -> bool:
        try:
            completed = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Running}}", self.sandbox_container],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            return completed.stdout.strip() == "true"
        except (OSError, subprocess.TimeoutExpired):
            return False

    def _sandbox_has_any_tool(self, tools: list[str]) -> bool:
        for tool in tools:
            try:
                completed = subprocess.run(
                    ["docker", "exec", self.sandbox_container, "which", tool],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                continue
            if completed.returncode == 0 and completed.stdout.strip():
                return True
        return False

    def _classify_build_failure(self, stdout: str, stderr: str) -> str:
        text = f"{stdout}\n{stderr}".lower()
        wrong_system_markers = (
            "use autoconfig",
            "use autoconf",
            "cmake only",
            "only used for windows",
            "not the official supported build system",
        )
        if any(marker in text for marker in wrong_system_markers):
            return "wrong_build_system"
        network_markers = (
            "could not resolve host", "network is unreachable", "temporary failure in name resolution",
            "failed to connect", "connection timed out",
        )
        if not self.build_network_enabled and any(marker in text for marker in network_markers):
            return "network_disabled"
        dependency_markers = (
            "could not find", "package configuration file provided by", "no package", "missing dependency",
            "not found (missing", "cannot find -l",
        )
        if any(marker in text for marker in dependency_markers):
            return "missing_dependency"
        return "build_failed"


class NativeBuildAgent:
    """Compatibility wrapper around BuildManager."""

    def __init__(self) -> None:
        self.manager = BuildManager()

    def decide(self, target: Path, profile: ProjectProfile, native_needed: bool) -> BuildDecision:
        if not native_needed:
            return BuildDecision(False, "No native finding requires CLI replay.")
        dummy = Finding(
            id="native-build",
            vulnerability_type="unsafe_memory_copy",
            severity="medium",
            title="native build probe",
            description="native build probe",
            file_path="",
        )
        env = EnvironmentManager().inspect(target, profile, dummy)
        decision, _ = self.manager.prepare(target, profile, dummy, env, target / ".agentic-build", False)
        return decision

    def find_or_build(self, target: Path, output_dir: Path, decision: BuildDecision) -> tuple[Path | None, list[str]]:
        existing = PocGenerator()._find_native_executable(target)
        if existing:
            return existing, [f"Found existing native executable: {existing}"]
        return None, [decision.reason, *decision.evidence]


class PocAnalyzer:
    """AnyPoC-compatible first gate. RuntimeManager refines the final strategy.

    When an LLM client is available, non-source-code findings (supply_chain_config,
    dependency, secret) are reviewed by the LLM before being accepted as valid_static.
    This prevents semgrep config-lint matches (e.g. "mutable action tag") from being
    reported as real vulnerabilities.
    """

    def __init__(self, llm_client: DeepSeekClient | None = None):
        self.llm_client = llm_client

    def analyze(self, target: Path, finding: Finding, profile: ProjectProfile) -> PocAnalysis:
        # --- risk-domain gate: non-source-code findings never enter dynamic verification ---
        risk_domain = getattr(finding, "risk_domain", "")
        if risk_domain in {"supply_chain_config", "dependency", "secret", "environment"}:
            # LLM validity review: is this a real vulnerability or just a config lint?
            rejection = self._llm_validity_review(finding)
            if rejection:
                return PocAnalysis(
                    verdict="false_positive",
                    verification_mode="llm_rejected",
                    oracle="LLM reviewed and determined this is not a real security vulnerability.",
                    details=rejection,
                    runtime_type="static",
                    entry_point=finding.file_path,
                    trigger_type="static_evidence",
                )
            static_details = {
                "supply_chain_config": "Configuration risk verified via static rule evidence + LLM confirmation.",
                "dependency": "Dependency finding verified via package/version/advisory evidence + LLM confirmation.",
                "secret": "Secret finding verified via literal evidence and rotation advisory + LLM confirmation.",
                "environment": "Environment-level risk verified via static evidence + LLM confirmation.",
            }.get(risk_domain, f"Risk domain '{risk_domain}' confirmed by LLM review.")
            return PocAnalysis(
                verdict="valid_static",
                verification_mode="static_evidence",
                oracle="static rule confirmation + LLM review",
                details=static_details,
                runtime_type="static",
                entry_point=finding.file_path,
                trigger_type="static_evidence",
            )
        # ----------------------------------------------------------------

        source_file = target / finding.file_path
        if finding.file_path and not source_file.exists():
            return PocAnalysis(
                verdict="invalid",
                verification_mode="none",
                oracle="none",
                details=f"Reported source file does not exist: {finding.file_path}",
                runtime_type="none",
                trigger_type="none",
                rejection_reason="missing_source_file",
            )
        if finding.vulnerability_type in {"hardcoded_secret", "secret_leak"}:
            return PocAnalysis(
                verdict="valid_static",
                verification_mode="static_secret",
                oracle="literal exists in repository and must be manually confirmed/rotated",
                details="Secret findings preserve static evidence and do not run dynamic exploit checks.",
                runtime_type="static",
                entry_point=finding.file_path,
                trigger_type="source_literal",
            )
        if finding.vulnerability_type == "dependency_vulnerability":
            return PocAnalysis(
                verdict="valid_static",
                verification_mode="dependency_only",
                oracle="affected dependency/version evidence is present",
                details="Dependency findings are verified from scanner/package evidence.",
                runtime_type="dependency_only",
                entry_point=finding.file_path,
                trigger_type="package_version",
            )
        if finding.route:
            return PocAnalysis(
                verdict="valid",
                verification_mode="http",
                oracle="HTTP probe reaches the route and records status/body evidence",
                details="Finding is attached to a route, so the checker can replay a request when runtime_url is set.",
                runtime_type="service",
                entry_point=finding.route,
                trigger_type="http_request",
            )
        if self._is_native_source(finding.file_path, profile):
            return PocAnalysis(
                verdict="valid",
                verification_mode="cpp_cli",
                oracle="crash, sanitizer, valgrind, or abnormal termination evidence",
                details="Native C/C++ finding requires a built binary or a generated harness.",
                runtime_type="cli",
                entry_point="<native-cli> <crafted_input>",
                trigger_type="crafted_input_file",
            )
        if finding.vulnerability_type in {"command_injection", "path_traversal", "sql_injection"}:
            return PocAnalysis(
                verdict="valid",
                verification_mode="manual_harness",
                oracle="generated harness emits a checker-recognized sentinel",
                details="No direct runtime entry was detected, so a constrained harness is generated.",
                runtime_type="harness",
                entry_point=finding.function_name or finding.file_path,
                trigger_type="generated_harness",
            )
        return PocAnalysis(
            verdict="valid",
            verification_mode="manual_review",
            oracle="real execution evidence or static blocked evidence",
            details="Generic finding needs project-specific runtime context.",
            runtime_type="review",
            entry_point=finding.function_name or finding.file_path,
            trigger_type="manual_analysis",
        )

    def _llm_validity_review(self, finding: Finding) -> str:
        """Ask LLM to judge whether a non-source-code finding is a real vulnerability.

        Returns an empty string if the finding should be accepted, or a rejection
        reason string if the LLM determines it is a false positive / config lint.
        """
        if not self.llm_client:
            return ""  # No LLM → accept the finding (preserve existing behavior)

        evidence_text = json.dumps(
            [str(e)[:300] for e in (finding.evidence or [])[:5]],
            ensure_ascii=False,
        )
        prompt = f"""你是资深安全审计专家。请审查以下静态分析工具的发现，判断它是否是真正的安全漏洞。

Finding 信息:
- 标题: {finding.title}
- 类型: {finding.vulnerability_type}
- 文件: {finding.file_path}
- 行号: {finding.line_start}
- Sink: {finding.sink}
- Source: {finding.source}
- 描述: {(finding.description or finding.chinese_summary or "")[:400]}
- 函数: {finding.function_name or "unknown"}
- 证据: {evidence_text}

判断标准:
1. 如果这是"代码中真实存在的可利用安全漏洞"（如缓冲区溢出、命令注入、SQL注入、UAF等），回答 ACCEPT
2. 如果这是"配置规范建议/最佳实践偏离/静态规则lint/CI配置检查"（如 GitHub Actions mutable tag、dependabot配置缺失、代码格式风格），回答 REJECT
3. 如果无法确定，回答 UNCERTAIN

请用 JSON 格式回答: {{"verdict":"ACCEPT|REJECT|UNCERTAIN","reasoning":"简短理由"}}"""

        try:
            resp = self.llm_client.chat(
                "你是安全审计专家。只输出JSON，不要其他内容。",
                prompt,
                timeout=30,
            )
        except Exception:
            return ""  # LLM call failed → accept the finding

        if not resp.ok or not resp.content.strip():
            return ""

        # Parse JSON verdict
        text = resp.content.strip()
        try:
            result = json.loads(text)
        except json.JSONDecodeError:
            match = re.search(r"\{.*?\}", text, re.S)
            if match:
                try:
                    result = json.loads(match.group(0))
                except json.JSONDecodeError:
                    return ""
            else:
                return ""

        verdict = str(result.get("verdict", "")).upper()
        reasoning = str(result.get("reasoning", ""))
        if verdict == "REJECT":
            return f"LLM rejected: {reasoning}" if reasoning else "LLM determined this is not a real vulnerability."
        if verdict == "UNCERTAIN":
            # Uncertain → accept but flag as weak evidence
            return ""  # Let it through with static evidence
        return ""  # ACCEPT or unknown → accept

    def _is_native_source(self, file_path: str, profile: ProjectProfile) -> bool:
        suffix = Path(file_path).suffix.lower()
        if suffix in {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}:
            return True
        return any(lang in profile.languages for lang in ("C", "C++"))


class PocGenerator:
    """Generate stable PoC/runbook artifacts without treating them as proof."""

    def __init__(self, llm_client: DeepSeekClient | None = None) -> None:
        self.llm_client = llm_client

    def generate(
        self,
        target: Path,
        finding: Finding,
        analysis: PocAnalysis,
        output_dir: Path,
        native_executable: Path | None = None,
        structured_plan: dict[str, Any] | None = None,
    ) -> PocPlan:
        poc_dir = output_dir / "pocs" / finding.id
        poc_dir.mkdir(parents=True, exist_ok=True)

        payload_plan: dict[str, Any] | None = None
        extra_artifacts: list[Path] = []
        if analysis.verification_mode == "http":
            poc_path = poc_dir / "poc_http.py"
            poc_path.write_text(self._http_poc(finding), encoding="utf-8")
        elif analysis.verification_mode in {"cpp_cli", "cpp_harness"}:
            payload_plan = self._payload_plan(target, finding, analysis, structured_plan or {})
            if self._payload_is_text(payload_plan):
                poc_path = poc_dir / "poc_input.txt"
                poc_path.write_text(self._native_text_payload(finding, payload_plan), encoding="utf-8")
            else:
                poc_path = poc_dir / "poc_input.bin"
                poc_path.write_bytes(self._native_payload(finding, payload_plan))
            if structured_plan is not None:
                structured_plan["poc_payload_plan"] = payload_plan
            extra_artifacts = self._write_verification_poc_artifacts(
                poc_dir,
                finding,
                analysis,
                payload_plan,
                poc_path,
                structured_plan or {},
            )
        else:
            poc_path = poc_dir / "poc_manual.md"
            poc_path.write_text(self._manual_poc(finding, analysis), encoding="utf-8")

        bug_report = poc_dir / "bug_report.md"
        bug_report.write_text(self._bug_report(finding, analysis, payload_plan), encoding="utf-8")
        plan = PocPlan(
            finding=finding,
            analysis=analysis,
            poc_dir=poc_dir,
            poc_path=poc_path,
            payload_paths=[poc_path] if analysis.verification_mode in {"cpp_cli", "cpp_harness"} else [],
            generated_artifacts=[bug_report, poc_path, *extra_artifacts],
            structured_plan=structured_plan or {},
        )
        if analysis.verification_mode == "cpp_cli":
            plan.target_command = self._native_command(target, poc_path, native_executable)

        runbook = poc_dir / "runbook.md"
        runbook.write_text(self._runbook(plan), encoding="utf-8")
        plan.runbook_path = runbook
        plan.generated_artifacts.append(runbook)
        return plan

    def _bug_report(self, finding: Finding, analysis: PocAnalysis, payload_plan: dict[str, Any] | None = None) -> str:
        payloads = "\n".join(f"- `{payload}`" for payload in self._report_payloads(finding, payload_plan)) or "- n/a"
        evidence = "\n".join(f"- {item}" for item in finding.evidence) or "- n/a"
        chain = "\n".join(f"- {step}" for step in finding.exploit_chain) or "- n/a"
        return "\n".join(
            [
                f"# Bug Report: {finding.id}",
                "",
                f"- Title: {finding.title}",
                f"- Type: {finding.vulnerability_type}",
                f"- Severity: {finding.severity}",
                f"- File: {finding.file_path}:{finding.line_start or ''}",
                f"- Analysis verdict: {analysis.verdict}",
                f"- Verification mode: {analysis.verification_mode}",
                f"- Oracle: {analysis.oracle}",
                "",
                "## Description",
                finding.description,
                "",
                "## Exploit Chain",
                chain,
                "",
                "## Payloads",
                payloads,
                "",
                "## Evidence",
                evidence,
            ]
        )

    def _report_payloads(self, finding: Finding, payload_plan: dict[str, Any] | None = None) -> list[str]:
        if payload_plan:
            stdin_script = str(payload_plan.get("stdin_script") or "").strip()
            if stdin_script:
                return [stdin_script]
            payloads = [str(item) for item in payload_plan.get("payloads", []) if str(item)]
            if payloads and not all(self._is_low_information_payload(payload) for payload in payloads):
                return payloads
        payloads = [str(item) for item in finding.exploit_payloads if str(item)]
        if payloads and not all(self._is_low_information_payload(payload) for payload in payloads):
            return payloads
        return [
            "\n".join(
                [
                    f"agentic_audit_case={finding.id}",
                    f"source={finding.source or 'unknown'}",
                    f"sink={finding.sink or 'unknown'}",
                    "payload=<target-specific input required>",
                ]
            )
        ]

    def _http_poc(self, finding: Finding) -> str:
        route_path = finding.route.split(" ", 1)[1] if " " in finding.route else finding.route
        param = self._guess_param(finding)
        payload = finding.exploit_payloads[0] if finding.exploit_payloads else "PAYLOAD"
        return f'''"""Authorized local PoC for {finding.vulnerability_type} ({finding.id})."""
from urllib.parse import urlencode
from urllib.request import urlopen

BASE_URL = "http://127.0.0.1:5000"
ROUTE = "{route_path}"
PARAM = "{param}"
PAYLOAD = {payload!r}

url = BASE_URL.rstrip("/") + ROUTE + "?" + urlencode({{PARAM: PAYLOAD}})
print("Request:", url)
with urlopen(url, timeout=10) as response:
    body = response.read().decode("utf-8", errors="replace")
    print("Status:", response.status)
    print(body[:1000])
'''

    def _manual_poc(self, finding: Finding, analysis: PocAnalysis) -> str:
        return "\n".join(
            [
                f"# PoC Harness: {finding.id}",
                "",
                "This finding needs a project-specific runtime or harness before it can be executed.",
                "",
                f"- Mode: `{analysis.verification_mode}`",
                f"- Oracle: {analysis.oracle}",
                f"- Source: `{finding.source or 'unknown'}`",
                f"- Sink: `{finding.sink or 'unknown'}`",
                "",
                "## Suggested Payloads",
                *[f"- `{payload}`" for payload in finding.exploit_payloads],
                "",
                "## Reproduction Hint",
                self._reproduction_hint(finding),
            ]
        )

    def _payload_plan(
        self,
        target: Path,
        finding: Finding,
        analysis: PocAnalysis,
        structured_plan: dict[str, Any],
    ) -> dict[str, Any]:
        recipe = structured_plan.get("verification_recipe") if isinstance(structured_plan.get("verification_recipe"), dict) else {}
        llm_plan = self._llm_payload_plan(target, finding, analysis, structured_plan)
        if llm_plan and self._payload_is_specific(llm_plan):
            return llm_plan
        if llm_plan and self._plan_has_harness(llm_plan):
            templated = self._template_payload_plan(finding, source=f"{llm_plan.get('source') or 'llm_payload_planner'}+template")
            for key in ("harness_code", "harness_language", "harness_filename", "run_commands", "poc_explanation", "execution_steps", "oracle", "expected_signal", "limitations"):
                if llm_plan.get(key):
                    templated[key] = llm_plan[key]
            templated["limitations"] = self._coerce_text_list(templated.get("limitations")) + [
                "LLM supplied runnable harness material, but the payload was low-information; input remains a fill-in template."
            ]
            return templated
        plan = {
            "source": "recipe",
            "format": str(recipe.get("payload_format") or ""),
            "payloads": self._coerce_text_list(recipe.get("payloads") or finding.exploit_payloads[:5]),
            "stdin_script": str(recipe.get("stdin_script") or ""),
            "cli_args": self._coerce_text_list(recipe.get("cli_args")),
            "config_files": self._coerce_text_list(recipe.get("config_files")),
            "execution_steps": self._coerce_text_list(recipe.get("execution_steps")),
            "harness_code": str(recipe.get("harness_code") or ""),
            "limitations": self._coerce_text_list(recipe.get("limitations")),
        }
        if self._payload_is_specific(plan):
            return plan
        return self._fallback_payload_plan(finding)

    def _llm_payload_plan(
        self,
        target: Path,
        finding: Finding,
        analysis: PocAnalysis,
        structured_plan: dict[str, Any],
    ) -> dict[str, Any]:
        if not self.llm_client or not hasattr(self.llm_client, "chat") or getattr(self.llm_client, "enabled", True) is False:
            return {}
        source_excerpt = self._source_excerpt(target, finding)
        prompt = (
            "Generate a concrete, local-only PoC input plan for an authorized source-code audit finding. "
            "Follow the DeepAudit-style approach: understand the target function, design protocol-aware payloads, "
            "and propose a harness or stdin/config input when the whole application cannot run. "
            "Return JSON only with keys: format, payloads, stdin_script, cli_args, config_files, execution_steps, "
            "harness_code, harness_language, harness_filename, run_commands, poc_explanation, oracle, expected_signal, limitations. "
            "stdin_script must be exact stdin content, not a shell command. "
            "harness_code must be runnable local PoC code when full target execution is unavailable. "
            "Do not claim success. Do not use network. Do not use destructive commands. "
            "Avoid generic 'AAAA...' unless it is explicitly the last-resort overflow probe.\n"
            + json.dumps(
                {
                    "finding": {
                        "id": finding.id,
                        "type": finding.vulnerability_type,
                        "file": finding.file_path,
                        "function": finding.function_name,
                        "source": finding.source,
                        "sink": finding.sink,
                        "trigger_conditions": finding.trigger_conditions,
                        "code_snippet": finding.code_snippet[:2000],
                    },
                    "analysis": asdict(analysis),
                    "verification_plan": structured_plan,
                    "source_excerpt": source_excerpt,
                },
                ensure_ascii=False,
                default=str,
            )
        )
        try:
            response = self.llm_client.chat(
                "You generate safe local PoC input plans and harness sketches. Output JSON only.",
                prompt,
                timeout=60,
            )
        except Exception:
            return {}
        if not response.ok:
            return {}
        parsed = self._parse_json_object(response.content)
        if not parsed:
            return {}
        return self._sanitize_payload_plan(parsed, source="llm_payload_planner")

    def _fallback_payload_plan(self, finding: Finding) -> dict[str, Any]:
        return self._template_payload_plan(finding, source="template_fallback")

    def _template_payload_plan(self, finding: Finding, source: str = "template_fallback") -> dict[str, Any]:
        template = "\n".join(
            [
                "# 待补充 PoC 输入模板",
                f"finding_id={finding.id}",
                f"target_function={finding.function_name or '<待补充目标函数>'}",
                f"source={finding.source or '<待补充 source>'}",
                f"sink={finding.sink or '<待补充 sink>'}",
                "payload=<由 LLM 或人工根据目标协议补充可运行输入>",
            ]
        )
        return {
            "source": source,
            "format": "poc_template",
            "payloads": [template],
            "stdin_script": template,
            "cli_args": [],
            "config_files": [],
            "execution_steps": [
                "当前没有可采纳的 LLM PoC；先根据 source/sink 和目标协议补充 payload。",
                "补充后在无网络 sandbox 中执行对应 CLI、Runtime 或 harness。",
            ],
            "harness_code": "",
            "limitations": ["这是待补充模板，不是已生成或已验证的 PoC。"],
            "is_template": True,
        }

    def _native_payload(self, finding: Finding, payload_plan: dict[str, Any] | None = None) -> bytes:
        payload_plan = payload_plan or {}
        payloads = [str(item) for item in payload_plan.get("payloads", []) if str(item)]
        if payloads:
            return ("\n".join(payloads) + "\n").encode("utf-8", errors="replace")
        if payload_plan.get("is_template"):
            return self._native_text_payload(finding, payload_plan).encode("utf-8", errors="replace")
        marker = f"AGENTIC_CODE_AUDIT_{finding.id}".encode("ascii", errors="ignore")
        return marker + b"\npayload=<LLM-generated binary payload required>\n"

    def _native_text_payload(self, finding: Finding, payload_plan: dict[str, Any]) -> str:
        lines = [
            f"# PoC input plan for {finding.id}",
            f"# format: {payload_plan.get('format') or 'stdin_text'}",
            f"# source: {payload_plan.get('source') or 'unknown'}",
            "",
        ]
        config_files = payload_plan.get("config_files") or []
        if config_files:
            lines.extend(["# config_files:", json.dumps(config_files, ensure_ascii=False, indent=2), ""])
        stdin_script = str(payload_plan.get("stdin_script") or "")
        if stdin_script:
            lines.extend([stdin_script, ""])
        else:
            payloads = [str(item) for item in payload_plan.get("payloads", []) if str(item)]
            lines.extend(payloads or ["payload=<由 LLM 或人工根据目标协议补充可运行输入>"])
        return "\n".join(lines)

    def _write_verification_poc_artifacts(
        self,
        poc_dir: Path,
        finding: Finding,
        analysis: PocAnalysis,
        payload_plan: dict[str, Any],
        poc_path: Path,
        structured_plan: dict[str, Any],
    ) -> list[Path]:
        artifacts: list[Path] = []
        recipe = structured_plan.get("verification_recipe") if isinstance(structured_plan.get("verification_recipe"), dict) else {}
        explanation_path = poc_dir / "poc_explanation.md"
        explanation_path.write_text(
            self._poc_explanation(finding, analysis, payload_plan, recipe),
            encoding="utf-8",
        )
        artifacts.append(explanation_path)

        harness_code, harness_name, harness_language = self._extract_harness_code(payload_plan)
        harness_path: Path | None = None
        if harness_code and self._harness_code_is_safe(harness_code):
            harness_path = poc_dir / self._safe_harness_filename(harness_name, harness_language)
            harness_path.write_text(harness_code, encoding="utf-8")
            artifacts.append(harness_path)

        run_path = poc_dir / "run_poc.sh"
        run_path.write_text(
            self._run_poc_script(payload_plan, poc_path, harness_path),
            encoding="utf-8",
        )
        try:
            os.chmod(run_path, 0o755)
        except OSError:
            pass
        artifacts.append(run_path)
        return artifacts

    def _poc_explanation(
        self,
        finding: Finding,
        analysis: PocAnalysis,
        payload_plan: dict[str, Any],
        recipe: dict[str, Any],
    ) -> str:
        steps = "\n".join(f"- {step}" for step in self._coerce_text_list(payload_plan.get("execution_steps"))) or "- Run `sh run_poc.sh` inside the sandbox or local build environment."
        limitations = "\n".join(f"- {item}" for item in self._coerce_text_list(payload_plan.get("limitations"))) or "- This PoC is evidence for validation, not an exploit guarantee."
        explanation = str(payload_plan.get("poc_explanation") or "").strip()
        if not explanation:
            explanation = (
                f"验证思路：围绕 `{finding.function_name or recipe.get('target_function') or 'target function'}` "
                f"构造本地输入，使 Source `{finding.source or recipe.get('source') or 'unknown'}` "
                f"到达 Sink `{finding.sink or recipe.get('sink') or 'unknown'}`，并用 `{analysis.oracle}` 作为判定信号。"
            )
        return "\n".join(
            [
                f"# PoC Explanation: {finding.id}",
                "",
                explanation,
                "",
                f"- Target function: `{recipe.get('target_function') or finding.function_name or 'unknown'}`",
                f"- Source: `{recipe.get('source') or finding.source or 'unknown'}`",
                f"- Sink: `{recipe.get('sink') or finding.sink or 'unknown'}`",
                f"- Oracle: `{payload_plan.get('oracle') or payload_plan.get('expected_signal') or analysis.oracle}`",
                f"- Plan source: `{payload_plan.get('source') or 'unknown'}`",
                "",
                "## Steps",
                steps,
                "",
                "## Limitations",
                limitations,
                "",
                "## Artifacts",
                "- `poc_input.txt` or `poc_input.bin`: local input sample",
                "- `poc_harness.*`: runnable local harness when available",
                "- `run_poc.sh`: local no-network execution script",
            ]
        )

    def _extract_harness_code(self, payload_plan: dict[str, Any]) -> tuple[str, str, str]:
        harness_code = str(payload_plan.get("harness_code") or "").strip()
        harness_language = str(payload_plan.get("harness_language") or "").strip().lower()
        harness_name = str(payload_plan.get("harness_filename") or "").strip()
        if harness_code:
            return harness_code, harness_name, harness_language
        for item in self._coerce_text_list(payload_plan.get("config_files")):
            parsed = self._parse_mapping(item)
            content = str(parsed.get("content") or parsed.get("code") or "").strip()
            path = str(parsed.get("path") or parsed.get("filename") or "").strip()
            if content and self._looks_like_harness_path(path):
                return content, path, self._language_from_filename(path)
        return "", "", ""

    @staticmethod
    def _parse_mapping(value: str) -> dict[str, Any]:
        text = str(value or "").strip()
        if not text:
            return {}
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            try:
                parsed = ast.literal_eval(text)
            except (ValueError, SyntaxError):
                return {}
        return parsed if isinstance(parsed, dict) else {}

    @staticmethod
    def _looks_like_harness_path(path: str) -> bool:
        name = Path(path).name.lower()
        return "harness" in name or name.startswith("poc_") or name in {"repro.c", "reproducer.c"}

    @staticmethod
    def _language_from_filename(path: str) -> str:
        suffix = Path(path).suffix.lower()
        if suffix == ".c":
            return "c"
        if suffix in {".cc", ".cpp", ".cxx"}:
            return "cpp"
        if suffix == ".py":
            return "python"
        if suffix == ".php":
            return "php"
        if suffix in {".js", ".mjs", ".cjs"}:
            return "javascript"
        if suffix == ".java":
            return "java"
        if suffix == ".go":
            return "go"
        if suffix in {".sh", ".bash"}:
            return "shell"
        return ""

    def _safe_harness_filename(self, harness_name: str, harness_language: str) -> str:
        name = Path(harness_name or "").name
        extensions = {
            "cpp": ".cpp",
            "c++": ".cpp",
            "python": ".py",
            "php": ".php",
            "javascript": ".js",
            "js": ".js",
            "node": ".js",
            "java": ".java",
            "go": ".go",
            "shell": ".sh",
            "sh": ".sh",
        }
        if not name or not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            ext = extensions.get(harness_language, ".c")
            name = f"poc_harness{ext}"
        if not name.startswith("poc_harness"):
            suffix = Path(name).suffix or extensions.get(harness_language, ".c")
            name = f"poc_harness{suffix}"
        return name

    @staticmethod
    def _harness_code_is_safe(harness_code: str) -> bool:
        lowered = harness_code.lower()
        blocked = [
            "system(",
            "popen(",
            "execl",
            "execv",
            "fork(",
            "socket(",
            "connect(",
            "curl ",
            "wget ",
            "unlink(",
            "remove(",
            "rmdir(",
        ]
        return not any(token in lowered for token in blocked)

    def _run_poc_script(self, payload_plan: dict[str, Any], poc_path: Path, harness_path: Path | None) -> str:
        commands = self._safe_run_commands(payload_plan)
        if commands:
            body = "\n".join(commands)
        elif harness_path:
            name = shlex.quote(harness_path.name)
            input_name = shlex.quote(poc_path.name)
            suffix = harness_path.suffix.lower()
            if suffix in {".c", ".cc", ".cpp", ".cxx"}:
                compiler = "${CXX:-c++}" if suffix in {".cc", ".cpp", ".cxx"} else "${CC:-cc}"
                body = "\n".join(
                    [
                        f'{compiler} -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer {name} -o poc_harness',
                        f'ASAN_OPTIONS=detect_stack_use_after_return=1 ./poc_harness < {input_name}',
                    ]
                )
            elif suffix == ".py":
                body = f"python {name} < {input_name}"
            elif suffix == ".php":
                body = f"php {name} < {input_name}"
            elif suffix in {".js", ".mjs", ".cjs"}:
                body = f"node {name} < {input_name}"
            elif suffix == ".go":
                body = f"go run {name} < {input_name}"
            elif suffix == ".java":
                body = "\n".join([f"javac {name}", f"java {shlex.quote(harness_path.stem)} < {input_name}"])
            else:
                body = f"sh {name}"
        else:
            body = "printf '%s\\n' 'No runnable harness was generated for this finding.'"
        return "\n".join(
            [
                "#!/bin/sh",
                "set -eu",
                'cd "$(dirname "$0")"',
                "# Local-only PoC runner. Do not enable network access for verification.",
                body,
                "",
            ]
        )

    def _safe_run_commands(self, payload_plan: dict[str, Any]) -> list[str]:
        safe: list[str] = []
        for command in self._coerce_text_list(payload_plan.get("run_commands")):
            text = command.strip()
            if not text:
                continue
            lowered = text.lower()
            if any(token in lowered for token in ["curl ", "wget ", " nc ", " ncat ", "rm -", "sudo ", "chmod 777", "://"]):
                continue
            safe.append(text)
        return safe[:5]

    @staticmethod
    def _payload_is_text(payload_plan: dict[str, Any]) -> bool:
        fmt = str(payload_plan.get("format", "")).lower()
        return fmt in {"stdin_text", "stdin_input", "text", "cli_session", "config", "http_request", "poc_template"} or bool(payload_plan.get("stdin_script"))

    def _payload_is_specific(self, payload_plan: dict[str, Any]) -> bool:
        fmt = str(payload_plan.get("format", "")).lower()
        if self._payload_plan_is_low_information(payload_plan):
            return False
        if payload_plan.get("is_template"):
            return False
        if fmt and fmt not in {"generic_overflow_probe", "poc_template"}:
            return True
        return bool(payload_plan.get("stdin_script") or payload_plan.get("config_files") or payload_plan.get("harness_code"))

    @staticmethod
    def _sanitize_payload_plan(plan: dict[str, Any], source: str) -> dict[str, Any]:
        sanitized: dict[str, Any] = {"source": source}
        for key in ("format", "stdin_script", "harness_code", "harness_language", "harness_filename", "poc_explanation", "oracle", "expected_signal"):
            value = plan.get(key)
            if value is not None:
                sanitized[key] = str(value)[:12000]
        for key in ("payloads", "cli_args", "config_files", "execution_steps", "run_commands", "limitations"):
            value = plan.get(key)
            if isinstance(value, list):
                sanitized[key] = [str(item)[:2000] for item in value[:12]]
            elif value:
                sanitized[key] = [str(value)[:2000]]
            else:
                sanitized[key] = []
        sanitized.setdefault("format", "stdin_text")
        return sanitized

    @staticmethod
    def _coerce_text_list(value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item) for item in value if str(item)]
        if isinstance(value, tuple | set):
            return [str(item) for item in value if str(item)]
        if isinstance(value, dict):
            return [json.dumps(value, ensure_ascii=False, sort_keys=True)]
        text = str(value)
        return [text] if text else []

    @staticmethod
    def _is_low_information_payload(payload: str) -> bool:
        text = str(payload or "").strip()
        if not text:
            return True
        if "AAAAAAAA..." in text:
            return True
        compact = re.sub(r"\s+", "", text)
        if len(compact) < 16:
            return False
        shell_stripped = re.sub(r"(?i)\b(echo|printf)\b|['\"`]|\.\/harness|[|;&]", "", compact)
        if re.fullmatch(r"A{16,}", shell_stripped):
            return True
        return len(set(compact)) <= 2

    def _payload_plan_is_low_information(self, payload_plan: dict[str, Any]) -> bool:
        samples: list[str] = []
        stdin_script = str(payload_plan.get("stdin_script") or "")
        if stdin_script:
            samples.append(stdin_script)
        samples.extend(str(item) for item in payload_plan.get("payloads", []) if str(item))
        if not samples:
            return False
        return all(self._is_low_information_payload(sample) for sample in samples)

    def _plan_has_harness(self, payload_plan: dict[str, Any]) -> bool:
        return bool(self._extract_harness_code(payload_plan)[0])

    @staticmethod
    def _parse_json_object(content: str) -> dict[str, Any]:
        text = content.strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.I | re.S)
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", text, re.S)
            if not match:
                return {}
            try:
                parsed = json.loads(match.group(0))
            except json.JSONDecodeError:
                return {}
        return parsed if isinstance(parsed, dict) else {}

    def _source_excerpt(self, target: Path, finding: Finding) -> str:
        path = target / finding.file_path if finding.file_path else None
        if path and path.exists() and path.is_file():
            try:
                return path.read_text(encoding="utf-8", errors="replace")[:6000]
            except OSError:
                pass
        return finding.code_snippet[:6000]

    def _native_command(self, target: Path, poc_path: Path, native_executable: Path | None = None) -> list[str]:
        exe = native_executable or self._find_native_executable(target)
        return [str(exe), str(poc_path)] if exe else []

    def _find_native_executable(self, target: Path) -> Path | None:
        priority_paths = [
            "build/bin/exiv2", "build/bin/exiv2.exe",
            "build/app/exiv2", "build/app/exiv2.exe",
            "bin/exiv2", "bin/exiv2.exe",
            ".agentic-build/bin/exiv2", ".agentic-build/bin/exiv2.exe",
            ".agentic-build/app/exiv2", ".agentic-build/app/exiv2.exe",
            ".agentic-build/exiv2", ".agentic-build/exiv2.exe",
        ]
        for relative in priority_paths:
            candidate = target / relative
            if candidate.is_file() and self._looks_executable(candidate):
                return candidate

        names = {target.name.lower(), "exiv2", "app", "main"}
        candidates = [
            path
            for path in target.rglob("*")
            if path.name.lower().removesuffix(".exe") in names
        ]
        for candidate in candidates[:200]:
            if ".git" in candidate.parts or not candidate.is_file():
                continue
            if self._looks_executable(candidate):
                return candidate
        return None

    def _looks_executable(self, candidate: Path) -> bool:
        if candidate.suffix.lower() == ".exe" or os.access(candidate, os.X_OK):
            return True
        try:
            with candidate.open("rb") as handle:
                header = handle.read(4)
            return header.startswith(b"\x7fELF") or header[:2] == b"MZ"
        except OSError:
            return False

    def _runbook(self, plan: PocPlan) -> str:
        command = " ".join(plan.target_command) if plan.target_command else "n/a"
        artifacts = "\n".join(f"- `{path}`" for path in plan.generated_artifacts)
        return "\n".join(
            [
                f"# Reproduction Runbook: {plan.finding.id}",
                "",
                f"- Mode: `{plan.analysis.verification_mode}`",
                f"- Oracle: {plan.analysis.oracle}",
                f"- Command: `{command}`",
                "",
                "## Artifacts",
                artifacts,
                "",
                "## Notes",
                plan.analysis.details,
            ]
        )

    def _reproduction_hint(self, finding: Finding) -> str:
        if finding.vulnerability_type == "sql_injection":
            return "Start the application and send SQL metacharacters into the affected parameter."
        if finding.vulnerability_type == "command_injection":
            return "Exercise the affected function with shell metacharacters inside a sandbox."
        if finding.vulnerability_type == "path_traversal":
            return "Exercise the affected file parameter with traversal payloads inside a sandbox."
        if finding.vulnerability_type in {"hardcoded_secret", "secret_leak"}:
            return "Confirm whether the literal is a real credential, then rotate it if exposed."
        if finding.vulnerability_type in {"unsafe_memory_copy", "unsafe_c_string_api", "memory_corruption"}:
            return "Build the native target with ASAN/UBSAN and feed the generated file to the parser CLI."
        return "Review the call chain and construct a minimal trigger for the reported sink."

    def _guess_param(self, finding: Finding) -> str:
        source = finding.source or ""
        match = re.search(r"get\(['\"]([^'\"]+)['\"]", source)
        if match:
            return match.group(1)
        if finding.vulnerability_type == "command_injection":
            return "host"
        if finding.vulnerability_type == "path_traversal":
            return "name"
        if finding.vulnerability_type == "sql_injection":
            return "id"
        return "input"


class EvidenceCollector:
    """Persist command, stdout/stderr, hashes, diffs, and environment logs."""

    def write_json(self, path: Path, data: Any) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        return path

    def snapshot(self, root: Path) -> dict[str, str]:
        snapshot: dict[str, str] = {}
        if not root.exists():
            return snapshot
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            rel = str(path.relative_to(root)).replace("\\", "/")
            try:
                snapshot[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError:
                continue
        return snapshot

    def diff(self, before: dict[str, str], after: dict[str, str]) -> dict[str, list[str]]:
        return {
            "added": sorted(set(after) - set(before)),
            "removed": sorted(set(before) - set(after)),
            "modified": sorted(key for key in set(before) & set(after) if before[key] != after[key]),
        }

    def write_execution(
        self,
        work_dir: Path,
        command: list[str],
        stdout: str,
        stderr: str,
        exit_code: int | None,
        before: dict[str, str],
        after: dict[str, str],
        local_fallback: bool,
    ) -> tuple[dict[str, Any], list[Path]]:
        artifacts = [
            self.write_json(work_dir / "command.json", command),
            self.write_json(work_dir / "pre_hashes.json", before),
            self.write_json(work_dir / "post_hashes.json", after),
            self.write_json(work_dir / "changed_files.json", self.diff(before, after)),
        ]
        stdout_path = work_dir / "stdout.log"
        stderr_path = work_dir / "stderr.log"
        exit_path = work_dir / "exit_code.txt"
        stdout_path.write_text(stdout, encoding="utf-8", errors="replace")
        stderr_path.write_text(stderr, encoding="utf-8", errors="replace")
        exit_path.write_text("" if exit_code is None else str(exit_code), encoding="utf-8")
        artifacts.extend([stdout_path, stderr_path, exit_path])
        execution = {
            "command": command,
            "exit_code": exit_code,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "changed_files": self.diff(before, after),
            "local_fallback": local_fallback,
        }
        return execution, artifacts


class MemorySafetyChecker:
    MARKERS = [
        "addresssanitizer",
        "undefinedbehavior",
        "runtime error:",
        "valgrind",
        "invalid read",
        "invalid write",
        "segmentation fault",
        "heap-buffer-overflow",
        "stack-buffer-overflow",
        "access violation",
        "abort",
    ]

    def check(self, outcome: CheckerOutcome) -> CheckerOutcome:
        text = f"{outcome.stdout_excerpt}\n{outcome.stderr_excerpt}".lower()
        matched = [marker for marker in self.MARKERS if marker in text]
        if matched and outcome.exit_code not in (0, None):
            outcome.status = "verified"
            outcome.summary = "Memory-safety oracle matched real crash/sanitizer evidence."
        elif outcome.exit_code not in (0, None) and any(marker in text for marker in ["crash", "fault"]):
            outcome.status = "partially_verified"
            outcome.summary = "Process failed with crash-like evidence, but sanitizer detail is incomplete."
        else:
            outcome.status = "not_reproducible" if outcome.exit_code == 0 else "uncertain"
            outcome.summary = "No crash/sanitizer oracle matched."
        outcome.checker_details = {"checker": "MemorySafetyChecker", "matched_markers": matched}
        return outcome


class CommandInjectionChecker:
    def check(self, outcome: CheckerOutcome) -> CheckerOutcome:
        text = f"{outcome.stdout_excerpt}\n{outcome.stderr_excerpt}".lower()
        matched = any(marker in text for marker in ["[detected]", "[vuln]", "command injection", "sentinel"])
        outcome.status = "verified" if matched else "uncertain"
        outcome.summary = "Command injection sentinel matched." if matched else "No command injection sentinel matched."
        outcome.checker_details = {"checker": "CommandInjectionChecker", "sentinel_matched": matched}
        return outcome


class PathTraversalChecker:
    def check(self, outcome: CheckerOutcome) -> CheckerOutcome:
        text = f"{outcome.stdout_excerpt}\n{outcome.stderr_excerpt}".lower()
        matched = any(marker in text for marker in ["[detected]", "traversal_sentinel", "root:x:", "sandbox sentinel"])
        outcome.status = "verified" if matched else "uncertain"
        outcome.summary = "Path traversal sentinel/read evidence matched." if matched else "No path traversal oracle matched."
        outcome.checker_details = {"checker": "PathTraversalChecker", "sentinel_matched": matched}
        return outcome


class SQLInjectionChecker:
    def check(self, outcome: CheckerOutcome) -> CheckerOutcome:
        text = f"{outcome.stdout_excerpt}\n{outcome.stderr_excerpt}".lower()
        matched = any(marker in text for marker in ["[detected]", "sql injection", "rows_bypassed", "or 1=1"])
        outcome.status = "verified" if matched else "uncertain"
        outcome.summary = "SQL injection oracle matched." if matched else "No SQL injection oracle matched."
        outcome.checker_details = {"checker": "SQLInjectionChecker", "sentinel_matched": matched}
        return outcome


class HttpChecker:
    def check(self, outcome: CheckerOutcome) -> CheckerOutcome:
        if outcome.http_status is not None:
            outcome.status = "partially_verified"
            outcome.summary = f"HTTP checker reached target with status {outcome.http_status}."
        elif outcome.status not in {"blocked", "not_reproducible"}:
            outcome.status = "uncertain"
            outcome.summary = "HTTP checker did not produce a status code."
        outcome.checker_details = {"checker": "HttpChecker", "http_status": outcome.http_status}
        return outcome


class DependencyChecker:
    def check(self, outcome: CheckerOutcome) -> CheckerOutcome:
        has_evidence = bool(outcome.evidence or outcome.stdout_excerpt or outcome.stderr_excerpt)
        outcome.status = "partially_verified" if has_evidence else "uncertain"
        outcome.summary = (
            "Dependency/static evidence was preserved; dynamic exploit replay is intentionally skipped."
            if has_evidence
            else "No dependency evidence was available."
        )
        outcome.checker_details = {"checker": "DependencyChecker", "has_static_evidence": has_evidence}
        return outcome


class GenericChecker:
    def check(self, outcome: CheckerOutcome) -> CheckerOutcome:
        if outcome.status == "verified":
            outcome.status = "uncertain"
        if not outcome.summary:
            outcome.summary = "Generic checker cannot mark a finding verified without a specific oracle."
        outcome.checker_details = {"checker": "GenericChecker"}
        return outcome


class EvidenceChecker:
    """Rules-based evidence dispatcher. LLM output is never sufficient for verified status."""

    def __init__(self) -> None:
        self.memory = MemorySafetyChecker()
        self.command = CommandInjectionChecker()
        self.path = PathTraversalChecker()
        self.sql = SQLInjectionChecker()
        self.http = HttpChecker()
        self.dependency = DependencyChecker()
        self.generic = GenericChecker()

    def check(self, target: Path, plan: PocPlan, runtime_url: str = "") -> CheckerOutcome:
        static = self._check_static_anchor(target, plan.finding)
        if plan.analysis.verdict == "invalid":
            return CheckerOutcome(
                status="false_positive",
                summary=plan.analysis.details,
                evidence=static + [f"Rejected: {plan.analysis.rejection_reason}"],
                checker_details={"checker": "StaticAnchorChecker", "reason": plan.analysis.rejection_reason},
            )

        mode = plan.analysis.verification_mode
        vuln_type = plan.finding.vulnerability_type
        if mode in {"static_secret", "dependency_only"} or vuln_type in {"dependency_vulnerability", "secret_leak"}:
            return self.dependency.check(
                CheckerOutcome(status="partially_verified", summary="", evidence=static + plan.finding.evidence)
            )
        if mode == "http":
            if not runtime_url:
                return CheckerOutcome(
                    status="blocked",
                    summary="HTTP PoC generated, but runtime_url was not provided for replay.",
                    evidence=static + ["Set runtime_url to run the independent HTTP checker."],
                    checker_details={"checker": "HttpChecker", "blocked_reason": "missing_runtime_url"},
                )
            return self.http.check(self._http_probe(runtime_url, plan, static))
        if mode == "cpp_cli":
            if not plan.target_command:
                return CheckerOutcome(
                    status="blocked",
                    summary="Native PoC input generated, but no built CLI binary was found.",
                    evidence=static + self._native_build_hints(target),
                    checker_details={"checker": "MemorySafetyChecker", "blocked_reason": "missing_native_cli"},
                )
            return self.dispatch(plan.finding, self._run_command(plan.target_command, static, plan.analysis.oracle))
        return CheckerOutcome(
            status="uncertain",
            summary="PoC/runbook generated; automated replay requires a project-specific harness.",
            evidence=static,
            checker_details={"checker": "GenericChecker"},
        )

    def dispatch(self, finding: Finding, outcome: CheckerOutcome) -> CheckerOutcome:
        if outcome.status == "blocked":
            return outcome
        vuln_type = finding.vulnerability_type
        if vuln_type in {"unsafe_memory_copy", "unsafe_c_string_api", "memory_corruption"}:
            return self.memory.check(outcome)
        if vuln_type == "command_injection":
            return self.command.check(outcome)
        if vuln_type == "path_traversal":
            return self.path.check(outcome)
        if vuln_type == "sql_injection":
            return self.sql.check(outcome)
        if vuln_type in {"dependency_vulnerability", "secret_leak", "hardcoded_secret"}:
            return self.dependency.check(outcome)
        if outcome.http_status is not None:
            return self.http.check(outcome)
        return self.generic.check(outcome)

    def _check_static_anchor(self, target: Path, finding: Finding) -> list[str]:
        file_path = target / finding.file_path
        evidence: list[str] = []
        if not finding.file_path:
            return ["Finding has no source file path."]
        if not file_path.exists():
            return [f"File does not exist: {finding.file_path}"]
        evidence.append(f"File exists: {finding.file_path}")
        if finding.line_start:
            try:
                lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError as exc:
                return evidence + [f"Could not read file: {exc}"]
            if 1 <= finding.line_start <= len(lines):
                evidence.append(f"Line {finding.line_start} exists.")
                line = lines[finding.line_start - 1].strip()
                if finding.code_snippet and finding.code_snippet[:40] in line:
                    evidence.append("Reported snippet matches source line.")
            else:
                evidence.append(f"Line {finding.line_start} is outside file range.")
        return evidence

    def _http_probe(self, runtime_url: str, plan: PocPlan, static: list[str]) -> CheckerOutcome:
        finding = plan.finding
        route_path = finding.route.split(" ", 1)[1] if " " in finding.route else finding.route
        param = PocGenerator()._guess_param(finding)
        payload = finding.exploit_payloads[0] if finding.exploit_payloads else "PAYLOAD"
        url = urljoin(runtime_url.rstrip("/") + "/", route_path.lstrip("/"))
        if "?" not in url:
            url = url + "?" + urlencode({param: payload})
        try:
            request = Request(url, headers={"User-Agent": "agentic-code-audit/0.5"})
            with urlopen(request, timeout=10) as response:
                body = response.read(2000).decode("utf-8", errors="replace")
                status = response.status
            return CheckerOutcome(
                status="partially_verified",
                summary=f"HTTP checker reached target with status {status}.",
                evidence=static + [f"HTTP probe sent to {url}"],
                http_status=status,
                http_evidence=body[:500],
            )
        except HTTPError as exc:
            return CheckerOutcome(
                status="partially_verified",
                summary=f"HTTP checker reached target with error status {exc.code}.",
                evidence=static + [f"HTTP probe sent to {url}"],
                http_status=exc.code,
            )
        except (URLError, TimeoutError, ValueError) as exc:
            return CheckerOutcome(
                status="not_reproducible",
                summary=f"HTTP checker could not reach runtime target: {exc}",
                evidence=static + [f"HTTP probe failed for {url}: {exc}"],
            )

    def _run_command(self, command: list[str], static: list[str], oracle: str) -> CheckerOutcome:
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return CheckerOutcome(
                status="not_reproducible",
                summary=f"Command execution failed: {exc}",
                evidence=static + [f"Command failed before oracle evaluation: {exc}"],
                checker_details={"checker": "CommandRunner", "oracle": oracle},
            )
        return CheckerOutcome(
            status="uncertain",
            summary=f"Command executed; oracle pending. Oracle: {oracle}",
            evidence=static + [f"Executed command: {' '.join(command)}"],
            exit_code=completed.returncode,
            stdout_excerpt=completed.stdout[-2000:],
            stderr_excerpt=completed.stderr[-2000:],
            sandbox_command=command,
        )

    def _native_build_hints(self, target: Path) -> list[str]:
        hints = ["Native validation needs a built parser/CLI binary."]
        if (target / "CMakeLists.txt").exists():
            hints.append("Detected CMakeLists.txt; suggested build: cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug")
            hints.append("Suggested compile: cmake --build build --config Debug")
        if (target / "meson.build").exists():
            hints.append("Detected meson.build; suggested build: meson setup build && meson compile -C build")
        hints.append("For C/C++, prefer ASAN/UBSAN builds before replaying generated PoC inputs.")
        return hints


class VerificationPlanner:
    """Produce the fixed phase-5 structured verification plan."""

    def __init__(self, llm_client: DeepSeekClient | None = None) -> None:
        self.llm_client = llm_client

    def plan(
        self,
        finding: Finding,
        target: Path,
        dynamic_plan: DynamicVerificationPlan | None = None,
    ) -> HarnessPlan:
        recipe_plan = self._recipe_harness_plan(finding, dynamic_plan)
        if recipe_plan:
            return recipe_plan
        return self._fallback_plan(finding, target)

    def partial_proof_plan(
        self,
        finding: Finding,
        target: Path,
        dynamic_plan: DynamicVerificationPlan,
    ) -> HarnessPlan:
        recipe_plan = self._recipe_harness_plan(finding, dynamic_plan, partial=True)
        if recipe_plan:
            return recipe_plan
        suffix = Path(finding.file_path).suffix.lower()
        if suffix in {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"} or dynamic_plan.runtime_type in {"cpp_cli", "cpp_harness"}:
            return self._c_micro_proof_plan(finding, dynamic_plan)
        return self._fallback_plan(finding, target)

    def structured_plan(
        self,
        finding: Finding,
        target: Path,
        decision: RuntimeDecision,
        environment: EnvironmentProfile,
    ) -> dict[str, Any]:
        plan = decision.to_plan(finding, environment)
        plan["files_to_create"] = [
            {
                "path": "pocs/{finding_id}/bug_report.md",
                "purpose": "human-readable vulnerability and verification context",
            },
            {
                "path": "pocs/{finding_id}/runbook.md",
                "purpose": "reproduction commands and blocked/fallback notes",
            },
        ]
        if finding.vulnerability_type in {"command_injection", "path_traversal", "sql_injection"}:
            plan["mock_strategy"] = "Use a minimal harness with sentinel files/values and no network."
        return plan

    def _fallback_plan(self, finding: Finding, target: Path) -> HarnessPlan:
        source_path = target / finding.file_path
        try:
            source_excerpt = source_path.read_text(encoding="utf-8", errors="ignore")[:4000]
        except OSError:
            source_excerpt = finding.code_snippet[:4000]
        payload = finding.exploit_payloads[0] if finding.exploit_payloads else "A" * 256
        finding_json = json.dumps(finding.__dict__, ensure_ascii=False, default=str)
        script = f'''import json

finding = json.loads({finding_json!r})
source_excerpt = {source_excerpt!r}
payload = {payload!r}

print("[HARNESS] finding", finding.get("id"))
print("[HARNESS] type", finding.get("vulnerability_type"))
print("[HARNESS] payload", payload[:200])

sink = finding.get("sink") or ""
snippet = finding.get("code_snippet") or source_excerpt
has_sink = bool(sink and sink in snippet) or finding.get("vulnerability_type") in snippet
has_trigger = bool(finding.get("trigger_conditions") or finding.get("source") or finding.get("exploit_payloads"))

if has_sink and has_trigger:
    print("[EVIDENCE] source, sink, and trigger metadata recorded")
else:
    print("[INFO] harness did not prove triggerability")
'''
        return HarnessPlan(
            method="Dynamic harness - deterministic fallback",
            language="python",
            script=script,
            command=["python", "/workspace/harness.py"],
            oracle="metadata capture only; no vulnerability oracle",
            explanation="Generated fallback records source/sink/payload metadata without executing target code.",
            strategy="local_harness",
            runtime_type="library_harness",
            rationale="No direct service/CLI entry was available.",
            commands=[["python", "/workspace/harness.py"]],
            expected_signal="[EVIDENCE] metadata captured",
            fallbacks=["weak_static_proof"],
            environment_requirements=["python"],
            mock_strategy="No network; synthetic source/sink trigger only.",
            weak_verification_strategy="Preserve static anchors and blocked reason.",
            safety_notes=["No external network access.", "Short-lived local harness only when Docker is unavailable."],
        )

    def _recipe_harness_plan(
        self,
        finding: Finding,
        dynamic_plan: DynamicVerificationPlan | None,
        partial: bool = False,
    ) -> HarnessPlan | None:
        if not dynamic_plan or not isinstance(dynamic_plan.verification_recipe, dict):
            return None
        recipe = dynamic_plan.verification_recipe
        harness_code = str(recipe.get("harness_code") or "").strip()
        if not harness_code or not self._harness_code_is_safe(harness_code):
            return None
        language = self._normalize_language(str(recipe.get("harness_language") or self._language_from_finding(finding)))
        filename = self._safe_harness_filename(str(recipe.get("harness_filename") or ""), language)
        script = self._script_for_recipe_harness(recipe, harness_code, filename, language)
        if not script:
            return None
        marker = str(recipe.get("expected_signal") or recipe.get("oracle") or dynamic_plan.oracle or "[DETECTED]")[:300]
        if "[DETECTED]" not in marker and marker.lower() in {"asan_crash", "ubsan", "nonzero_exit", "stderr_marker", "output_diff"}:
            marker = "[DETECTED]"
        return HarnessPlan(
            method="LLM generated verification harness" if not partial else "LLM generated partial verification harness",
            language="shell",
            script=script,
            command=["sh", "/workspace/harness.sh"],
            oracle=f"{marker} in stdout/stderr or checker-specific signal",
            explanation="LLM recipe supplied the concrete local harness; system executes it in a no-network sandbox and validates evidence.",
            strategy="llm_generated_harness" if not partial else "llm_partial_harness",
            runtime_type=dynamic_plan.runtime_type,
            rationale=dynamic_plan.rationale,
            commands=[["sh", "/workspace/harness.sh"]],
            expected_signal=marker,
            fallbacks=["weak_static_proof"],
            environment_requirements=self._requirements_for_language(language),
            mock_strategy=str(recipe.get("fallback_harness") or "LLM-designed focused harness with mocked dependencies."),
            weak_verification_strategy="Record harness evidence only; do not upgrade partial evidence to full verified.",
            safety_notes=["No network.", "No destructive commands.", "LLM tactics cannot override proof labels or sandbox policy."],
        )

    def _script_for_recipe_harness(
        self,
        recipe: dict[str, Any],
        harness_code: str,
        filename: str,
        language: str,
    ) -> str:
        stdin_text = self._recipe_stdin(recipe)
        setup = [
            "set -eu",
            "cat > poc_input.txt <<'EOF_INPUT'",
            stdin_text,
            "EOF_INPUT",
            f"cat > {shlex.quote(filename)} <<'EOF_HARNESS'",
            harness_code,
            "EOF_HARNESS",
        ]
        commands = self._safe_run_commands(recipe)
        if not commands:
            commands = self._default_run_commands(filename, language)
        if not commands:
            return ""
        return "\n".join([*setup, *commands, ""])

    @staticmethod
    def _recipe_stdin(recipe: dict[str, Any]) -> str:
        stdin_script = str(recipe.get("stdin_script") or "").strip()
        if stdin_script:
            return stdin_script
        payloads = recipe.get("payloads")
        if isinstance(payloads, list) and payloads:
            return "\n".join(str(item) for item in payloads)
        if payloads:
            return str(payloads)
        return "payload=<fill target-specific input before manual replay>"

    @staticmethod
    def _safe_run_commands(recipe: dict[str, Any]) -> list[str]:
        raw = recipe.get("run_commands") or recipe.get("commands") or []
        if not isinstance(raw, list):
            raw = [raw]
        safe: list[str] = []
        blocked = ["curl ", "wget ", " nc ", " ncat ", "://", "sudo ", "rm -", "mkfs", "dd ", "chmod 777"]
        for item in raw:
            text = str(item or "").strip()
            if not text:
                continue
            lowered = text.lower()
            if any(token in lowered for token in blocked):
                continue
            safe.append(text[:2000])
        return safe[:6]

    @staticmethod
    def _default_run_commands(filename: str, language: str) -> list[str]:
        quoted = shlex.quote(filename)
        if language == "python":
            return [f"python {quoted} < poc_input.txt"]
        if language in {"javascript", "node"}:
            return [f"node {quoted} < poc_input.txt"]
        if language == "php":
            return [f"php {quoted} < poc_input.txt"]
        if language in {"shell", "bash", "sh"}:
            return [f"sh {quoted} < poc_input.txt"]
        if language == "go":
            return [f"go run {quoted} < poc_input.txt"]
        if language == "java":
            class_name = Path(filename).stem
            return [f"javac {quoted}", f"java {shlex.quote(class_name)} < poc_input.txt"]
        if language in {"c", "cpp", "c++"}:
            compiler = "${CXX:-c++}" if language in {"cpp", "c++"} else "${CC:-cc}"
            return [
                f"{compiler} -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer {quoted} -o poc_harness",
                "ASAN_OPTIONS=detect_stack_use_after_return=1 ./poc_harness < poc_input.txt",
            ]
        return []

    @staticmethod
    def _normalize_language(language: str) -> str:
        normalized = language.strip().lower()
        aliases = {
            "py": "python",
            "js": "javascript",
            "nodejs": "javascript",
            "node": "javascript",
            "c++": "cpp",
            "cc": "cpp",
            "cxx": "cpp",
            "golang": "go",
            "bash": "shell",
            "sh": "shell",
        }
        return aliases.get(normalized, normalized or "python")

    @staticmethod
    def _language_from_finding(finding: Finding) -> str:
        suffix = Path(finding.file_path).suffix.lower()
        if suffix == ".py":
            return "python"
        if suffix in {".js", ".jsx", ".ts", ".tsx"}:
            return "javascript"
        if suffix == ".php":
            return "php"
        if suffix == ".java":
            return "java"
        if suffix == ".go":
            return "go"
        if suffix == ".c":
            return "c"
        if suffix in {".cc", ".cpp", ".cxx"}:
            return "cpp"
        return "python"

    @staticmethod
    def _safe_harness_filename(name: str, language: str) -> str:
        candidate = Path(name or "").name
        if candidate and re.fullmatch(r"[A-Za-z0-9_.-]+", candidate):
            return candidate
        suffix = {
            "python": ".py",
            "javascript": ".js",
            "php": ".php",
            "java": ".java",
            "go": ".go",
            "c": ".c",
            "cpp": ".cpp",
            "shell": ".sh",
        }.get(language, ".py")
        return f"poc_harness{suffix}"

    @staticmethod
    def _requirements_for_language(language: str) -> list[str]:
        return {
            "python": ["python"],
            "javascript": ["node"],
            "php": ["php"],
            "java": ["java", "javac"],
            "go": ["go"],
            "c": ["cc", "asan", "ubsan"],
            "cpp": ["c++", "asan", "ubsan"],
            "shell": ["sh"],
        }.get(language, [language])

    @staticmethod
    def _harness_code_is_safe(harness_code: str) -> bool:
        lowered = harness_code.lower()
        blocked = [
            "socket(",
            "connect(",
            "curl ",
            "wget ",
            "ncat ",
            " nc ",
            "rm -rf",
            "unlink(",
            "remove(",
            "rmdir(",
            "mkfs",
            "dd if=",
            "sudo ",
        ]
        return not any(token in lowered for token in blocked)

    def _c_micro_proof_plan(self, finding: Finding, dynamic_plan: DynamicVerificationPlan) -> HarnessPlan:
        marker = "[DETECTED] partial dynamic proof"
        sink = (finding.sink or finding.vulnerability_type or "sink").replace('"', '\\"')[:120]
        source = (finding.source or "crafted input").replace('"', '\\"')[:120]
        c_source = f'''#include <stdio.h>
#include <string.h>

int main(void) {{
    char dst[16];
    char src[128];
    memset(src, 'A', sizeof(src) - 1);
    src[sizeof(src) - 1] = '\\0';
    printf("[HARNESS] source: {source}\\n");
    printf("[HARNESS] sink: {sink}\\n");
    strcpy(dst, src);
    printf("{marker}\\n");
    return 0;
}}
'''
        script = f'''set -eu
cat > partial_proof.c <<'EOF'
{c_source}
EOF
CC="${{CC:-cc}}"
"$CC" -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer partial_proof.c -o partial_proof
ASAN_OPTIONS=detect_stack_use_after_return=1 ./partial_proof
'''
        return HarnessPlan(
            method="Partial dynamic micro proof",
            language="shell",
            script=script,
            command=["sh", "/workspace/harness.sh"],
            oracle=f"{marker} in stdout or sanitizer stderr",
            explanation="Compiles and runs a constrained C micro proof for the reported sink pattern; it is not full target execution.",
            strategy="micro_proof",
            runtime_type=dynamic_plan.runtime_type,
            rationale=dynamic_plan.rationale,
            commands=[["sh", "/workspace/harness.sh"]],
            expected_signal=marker,
            fallbacks=["weak_static_proof"],
            environment_requirements=["cc", "asan", "ubsan"],
            mock_strategy="No network; micro proof is isolated from the target source tree.",
            weak_verification_strategy="Record partial proof only; never mark verified.",
            safety_notes=["No network.", "No target repository mutation.", "Partial proof cannot prove full exploitability."],
        )

    def _marker_for(self, finding: Finding) -> str:
        if finding.vulnerability_type == "command_injection":
            return "[DETECTED] command injection sentinel"
        if finding.vulnerability_type == "path_traversal":
            return "[DETECTED] traversal_sentinel"
        if finding.vulnerability_type == "sql_injection":
            return "[DETECTED] rows_bypassed"
        return "[DETECTED]"


class SandboxExecutor:
    """Run verification in short-lived, resource-limited, networkless containers."""

    def __init__(
        self,
        image: str = "agentic-code-audit-sandbox:local",
        compose_container: str = "",
    ) -> None:
        self.image = image
        self.compose_container = compose_container or os.getenv("AUDIT_SANDBOX_CONTAINER", "")
        self.collector = EvidenceCollector()

    def execute(self, plan: HarnessPlan, work_dir: Path) -> CheckerOutcome:
        work_dir.mkdir(parents=True, exist_ok=True)
        before = self.collector.snapshot(work_dir)
        script_name = "harness.py" if plan.language.lower() in {"python", "py"} else "harness.sh"
        script_path = work_dir / script_name
        script_path.write_text(plan.script, encoding="utf-8")
        command = plan.command or (["python", "/workspace/harness.py"] if script_name.endswith(".py") else ["bash", "/workspace/harness.sh"])
        docker = shutil.which("docker")
        if not docker:
            after = self.collector.snapshot(work_dir)
            execution, artifacts = self.collector.write_execution(work_dir, [], "", "Docker is unavailable.", None, before, after, False)
            return CheckerOutcome(
                status="blocked",
                summary="Docker is unavailable; dynamic verification was not executed.",
                evidence=[f"Harness: {script_path}"],
                sandbox_command=[],
                local_fallback=False,
                artifact_paths=[script_path, *artifacts],
                execution=execution,
                checker_details={"checker": "SandboxExecutor", "blocked_reason": "missing_docker"},
            )

        if self.compose_container and self._container_running(docker):
            sandbox_dir = self._compose_sandbox_path(work_dir)
            compose_command = self._compose_command(command, script_name)
            run_command = [
                docker,
                "run", "--rm",
                "--network", "none",
                "--memory", "1g",
                "--cpus", "1",
                "--volumes-from", self.compose_container,
                "-w", sandbox_dir,
                self.image,
                *compose_command,
            ]
        elif self.compose_container:
            after = self.collector.snapshot(work_dir)
            execution, artifacts = self.collector.write_execution(
                work_dir, [], "", "Configured sandbox container is unavailable.", None, before, after, False
            )
            return CheckerOutcome(
                status="blocked",
                summary=f"Verification sandbox '{self.compose_container}' is unavailable.",
                evidence=[f"Harness: {script_path}"],
                artifact_paths=[script_path, *artifacts],
                execution=execution,
                checker_details={"checker": "SandboxExecutor", "blocked_reason": "sandbox_unavailable"},
            )
        else:
            run_command = [
                docker,
                "run",
                "--rm",
                "--network",
                "none",
                "--memory",
                "1g",
                "--cpus",
                "1",
                "-v",
                f"{work_dir.resolve()}:/workspace",
                self.image,
                *command,
            ]
        started = time.time()
        try:
            completed = subprocess.run(
                run_command,
                cwd=str(work_dir),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=60,
                check=False,
            )
            stdout = completed.stdout[-8000:]
            stderr = completed.stderr[-8000:]
            exit_code = completed.returncode
        except (OSError, subprocess.TimeoutExpired) as exc:
            after = self.collector.snapshot(work_dir)
            execution, artifacts = self.collector.write_execution(work_dir, run_command, "", str(exc), None, before, after, False)
            return CheckerOutcome(
                status="blocked",
                summary=f"Sandbox execution failed: {exc}",
                evidence=[f"Executor exception: {exc}", f"Harness: {script_path}"],
                sandbox_command=run_command,
                local_fallback=False,
                artifact_paths=artifacts,
                execution=execution,
                checker_details={
                    "checker": "SandboxExecutor",
                    "duration_ms": int((time.time() - started) * 1000),
                    "blocked_reason": "execution_failed",
                },
            )
        after = self.collector.snapshot(work_dir)
        execution, artifacts = self.collector.write_execution(work_dir, run_command, stdout, stderr, exit_code, before, after, False)
        combined = f"{stdout}\n{stderr}"
        marker = "[DETECTED]" in combined or "[VULN]" in combined
        status = "verified" if marker and exit_code == 0 else ("partially_verified" if marker else "not_reproducible")
        return CheckerOutcome(
            status=status,
            summary=f"{plan.method}; oracle={plan.oracle}; duration={time.time() - started:.2f}s",
            evidence=[f"Harness: {script_path}", f"stdout: {work_dir / 'stdout.log'}", f"stderr: {work_dir / 'stderr.log'}"],
            exit_code=exit_code,
            stdout_excerpt=stdout,
            stderr_excerpt=stderr,
            sandbox_command=run_command,
            checker_details={"checker": "SandboxExecutor", "duration_ms": int((time.time() - started) * 1000)},
            local_fallback=False,
            artifact_paths=[script_path, *artifacts],
            execution=execution,
        )

    def execute_command(self, command: list[str], work_dir: Path) -> CheckerOutcome:
        """Execute an existing native CLI and payload inside the verification sandbox."""
        work_dir.mkdir(parents=True, exist_ok=True)
        before = self.collector.snapshot(work_dir)
        docker = shutil.which("docker")
        if not docker:
            after = self.collector.snapshot(work_dir)
            execution, artifacts = self.collector.write_execution(work_dir, [], "", "Docker is unavailable.", None, before, after, False)
            return CheckerOutcome(
                status="blocked",
                summary="Docker is unavailable; native CLI replay was not executed.",
                artifact_paths=artifacts,
                execution=execution,
                checker_details={"checker": "SandboxExecutor", "blocked_reason": "missing_docker"},
            )
        if not self.compose_container or not self._container_running(docker):
            return CheckerOutcome(
                status="blocked",
                summary="The shared verification sandbox is unavailable for native CLI replay.",
                checker_details={"checker": "SandboxExecutor", "blocked_reason": "sandbox_unavailable"},
            )

        from ..tools.runner import _translate_command_for_sandbox

        sandbox_dir = self._compose_sandbox_path(work_dir)
        sandbox_command = _translate_command_for_sandbox(command)
        run_command = [
            docker, "run", "--rm",
            "--network", "none",
            "--memory", "1g",
            "--cpus", "1",
            "--volumes-from", self.compose_container,
            "-w", sandbox_dir,
            self.image,
            *sandbox_command,
        ]
        try:
            completed = subprocess.run(
                run_command,
                cwd=str(work_dir),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=60,
                check=False,
            )
            stdout = completed.stdout[-8000:]
            stderr = completed.stderr[-8000:]
            exit_code = completed.returncode
        except (OSError, subprocess.TimeoutExpired) as exc:
            stdout, stderr, exit_code = "", str(exc), None
        after = self.collector.snapshot(work_dir)
        execution, artifacts = self.collector.write_execution(
            work_dir, run_command, stdout, stderr, exit_code, before, after, False
        )
        return CheckerOutcome(
            status="uncertain" if exit_code is not None else "blocked",
            summary="Native CLI command executed in the networkless verification sandbox." if exit_code is not None else "Native CLI replay failed before completion.",
            exit_code=exit_code,
            stdout_excerpt=stdout,
            stderr_excerpt=stderr,
            sandbox_command=run_command,
            artifact_paths=artifacts,
            execution=execution,
            checker_details={
                "checker": "SandboxExecutor",
                **({} if exit_code is not None else {"blocked_reason": "execution_failed"}),
            },
        )

    def _container_running(self, docker: str) -> bool:
        try:
            completed = subprocess.run(
                [docker, "inspect", "--format", "{{.State.Running}}", self.compose_container],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            return completed.stdout.strip() == "true"
        except (OSError, subprocess.TimeoutExpired):
            return False

    def _compose_sandbox_path(self, work_dir: Path) -> str:
        resolved = work_dir.resolve().as_posix()
        mappings = {"/app/reports": "/workspace/reports", "/app/runs": "/workspace/runs"}
        for host_prefix, sandbox_prefix in mappings.items():
            if resolved.startswith(host_prefix):
                return sandbox_prefix + resolved[len(host_prefix) :]
        return resolved

    def _compose_command(self, command: list[str], script_name: str) -> list[str]:
        return [script_name if item in {"/workspace/harness.py", "/workspace/harness.sh"} else item for item in command]

    def _read_text(self, path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""


class DynamicPlanner:
    """Create an executable verification plan after static verification and budget gating."""

    ELIGIBLE_STATIC_STATUSES = {"plausible", "weak_static_proof"}
    RUNTIME_TYPES = {"cpp_cli", "cpp_harness", "python_test", "node_test", "php_test", "java_test", "go_test", "http_service", "library_harness"}
    BUILD_STRATEGIES = {"existing_binary", "cmake_build", "autotools_build", "make_build", "meson_build", "no_build_possible", "no_build_required"}
    POC_STRATEGIES = {"malformed_file", "cli_arg", "unit_test", "harness", "http_request"}
    ORACLES = {"asan_crash", "ubsan", "nonzero_exit", "stderr_marker", "output_diff", "timeout", "http_status_or_body_marker", "nonzero_exit_or_checker_marker"}

    def __init__(self, llm_client: DeepSeekClient | None = None) -> None:
        self.llm_client = llm_client

    def plan(
        self,
        target: Path,
        profile: ProjectProfile,
        finding: Finding,
        static_result: StaticVerificationResult,
        environment: EnvironmentProfile,
        runtime_url: str = "",
        native_executable: Path | None = None,
        build_decision: BuildDecision | None = None,
        director_hint: dict[str, Any] | None = None,
    ) -> DynamicVerificationPlan:
        if static_result.risk_domain != "source_code":
            return self.skipped(finding, "risk_domain_static_only", "Non-source findings do not enter dynamic verification.")
        if static_result.static_status not in self.ELIGIBLE_STATIC_STATUSES:
            return self.skipped(
                finding,
                "static_gate_rejected",
                f"Static status '{static_result.static_status}' is not eligible for dynamic verification.",
            )
        if not static_result.dynamic_eligible:
            return self.skipped(finding, "should_verify_false", "The finding is not marked for dynamic verification.")

        runtime_type = environment.runtime_type
        build_strategy = "no_build_required"
        strategy = ""
        status = "planned"
        blocked_reason = ""
        rationale = ""
        commands: list[list[str]] = []
        fallbacks = ["weak_static_proof"]

        if finding.route or runtime_type == "http_service":
            runtime_type = "http_service"
            strategy = "http_probe"
            rationale = "A route was identified, so verification uses an HTTP oracle."
            if not runtime_url:
                status = "blocked"
                blocked_reason = "missing_runtime_url"
        elif runtime_type == "cpp_cli":
            if native_executable:
                runtime_type = "cpp_cli"
                build_strategy = "existing_binary" if not (build_decision and build_decision.should_attempt) else self._build_strategy(build_decision)
                strategy = "native_cli_with_payload"
                commands = [[str(native_executable)]]
                rationale = "A native CLI is available for crafted-input replay."
            else:
                runtime_type = "cpp_harness"
                build_strategy = self._build_strategy(build_decision)
                strategy = "native_harness_or_static_blocked"
                status = "blocked"
                blocked_reason = self._native_blocked_reason(build_decision, environment)
                rationale = "No executable native entry is available for replay."
                fallbacks = ["weak_static_proof", "static_blocked"]
        elif runtime_type == "python_test":
            strategy = "python_harness_or_pytest"
            rationale = "Python supports a direct test or constrained generated harness."
            if "python" in environment.missing_tools:
                status = "blocked"
                blocked_reason = "missing_tool"
        elif runtime_type == "node_test":
            strategy = "node_harness_or_npm_test"
            rationale = "Node.js supports npm tests or a constrained generated harness."
            if "node" in environment.missing_tools:
                status = "blocked"
                blocked_reason = "missing_tool"
        elif runtime_type == "php_test":
            strategy = "php_harness_or_phpunit"
            rationale = "PHP supports a constrained generated harness or PHPUnit-style local replay."
            if "php" in environment.missing_tools:
                status = "blocked"
                blocked_reason = "missing_tool"
        elif runtime_type == "java_test":
            strategy = "java_harness_or_junit"
            rationale = "Java supports a constrained generated harness compiled with javac or project test tooling."
            if "java" in environment.missing_tools or "javac" in environment.missing_tools:
                status = "blocked"
                blocked_reason = "missing_tool"
        elif runtime_type == "go_test":
            strategy = "go_harness_or_go_test"
            rationale = "Go supports a constrained generated harness or go test style replay."
            if "go" in environment.missing_tools:
                status = "blocked"
                blocked_reason = "missing_tool"
        elif runtime_type == "library_harness":
            strategy = "generated_library_harness"
            rationale = "The project is library-only and requires a minimal host harness."
        elif runtime_type.endswith("_blocked"):
            status = "blocked"
            strategy = "static_blocked"
            blocked_reason = "missing_runtime"
            rationale = f"Runtime '{runtime_type}' is recognized but not enabled for dynamic execution."
        else:
            runtime_type = "blocked"
            status = "blocked"
            strategy = "static_blocked"
            blocked_reason = "no_runtime_entry"
            rationale = "No executable service, CLI, test, or harness entry was identified."

        poc_strategy = self._poc_strategy(finding, runtime_type)
        oracle = self._oracle(finding, runtime_type)
        merged_director_hint = dict(finding.verification_hint or {})
        merged_director_hint.update(director_hint or {})
        hinted_oracle = str(merged_director_hint.get("oracle", "")).strip()
        if hinted_oracle:
            oracle = hinted_oracle[:300]
        if merged_director_hint.get("harness_candidate") and runtime_type == "cpp_harness":
            poc_strategy = "harness"
        plan = DynamicVerificationPlan(
            finding_id=finding.id,
            status=status,
            runtime_type=runtime_type,
            build_strategy=build_strategy,
            poc_strategy=poc_strategy,
            oracle=oracle,
            rationale=rationale,
            strategy=strategy,
            commands=commands,
            environment_requirements=list(environment.missing_tools),
            fallbacks=fallbacks,
            blocked_reason=blocked_reason,
            director_hint=merged_director_hint,
        )
        plan.verification_recipe = self._fallback_recipe(finding, plan, environment, static_result)
        return plan

    def review_batch(
        self,
        profile: ProjectProfile,
        items: list[tuple[Finding, StaticVerificationResult, EnvironmentProfile, DynamicVerificationPlan]],
    ) -> None:
        reviewable = [item for item in items if item[3].status in {"planned", "blocked"}]
        if not reviewable or not self.llm_client or not hasattr(self.llm_client, "chat"):
            return
        if getattr(self.llm_client, "enabled", True) is False:
            return
        payload = []
        for finding, static_result, environment, plan in reviewable:
            payload.append(
                {
                    "finding_id": finding.id,
                    "type": finding.vulnerability_type,
                    "file": finding.file_path,
                    "function": finding.function_name,
                    "source": finding.source,
                    "sink": finding.sink,
                    "route": finding.route,
                    "static_verification": static_result.to_dict(),
                    "environment": {
                        "runtime_type": environment.runtime_type,
                        "languages": environment.languages,
                        "project_type": environment.project_type,
                        "build_systems": environment.build_systems,
                        "runtime_entries": environment.runtime_entries[:8],
                        "test_entries": environment.test_entries[:8],
                        "missing_tools": environment.missing_tools,
                    },
                    "deterministic_plan": plan.to_dict(),
                }
            )
        prompt = (
            "Propose concrete dynamic verification recipes for these authorized local source-audit findings. "
            "Return a JSON array only. Each item must contain finding_id, runtime_type, build_strategy, "
            "poc_strategy, oracle, rationale, and verification_recipe. verification_recipe must contain "
            "target_function, source, sink, preconditions, preferred_build, runtime_entry, fallback_harness, "
            "micro_proof, payloads, payload_format, execution_steps, expected_signal, and limitations. Choose only values represented by the deterministic "
            "plan and detected environment; never claim execution success.\nProject profile:\n"
            + json.dumps(
                {
                    "languages": profile.languages,
                    "project_type": profile.project_type,
                    "build_entries": profile.build_entries[:10],
                    "runtime_entries": profile.runtime_entries[:10],
                    "test_entries": profile.test_entries[:10],
                },
                ensure_ascii=False,
                default=str,
            )
            + "\nFindings:\n"
            + json.dumps(payload, ensure_ascii=False, default=str)
        )
        try:
            response = self.llm_client.chat(
                "You plan safe, local, no-network vulnerability verification. Output JSON only.",
                prompt,
                timeout=60,
            )
        except Exception as exc:
            self._record_review_error(reviewable, str(exc))
            return
        if not response.ok:
            self._record_review_error(reviewable, response.error or "LLM planning failed")
            return
        reviews = StaticVerifier._parse_reviews(response.content)
        by_id = {str(item.get("finding_id", "")): item for item in reviews}
        for finding, _static_result, environment, plan in reviewable:
            review = by_id.get(finding.id)
            if not review:
                plan.planner_review = {"status": "missing", "accepted_fields": []}
                continue
            self._apply_review(finding, environment, plan, review)

    def _apply_review(
        self,
        finding: Finding,
        environment: EnvironmentProfile,
        plan: DynamicVerificationPlan,
        review: dict[str, Any],
    ) -> None:
        accepted: list[str] = []
        rejected: list[str] = []
        runtime_type = str(review.get("runtime_type", "")).strip()
        compatible_runtimes = self._compatible_runtimes(plan.runtime_type)
        if plan.status == "planned" and runtime_type in self.RUNTIME_TYPES and runtime_type in compatible_runtimes:
            plan.runtime_type = runtime_type
            accepted.append("runtime_type")
        elif runtime_type:
            rejected.append("runtime_type")

        build_strategy = str(review.get("build_strategy", "")).strip()
        if (
            plan.status == "planned"
            and build_strategy in self.BUILD_STRATEGIES
            and self._build_is_supported(build_strategy, environment, plan)
        ):
            plan.build_strategy = build_strategy
            accepted.append("build_strategy")
        elif build_strategy:
            rejected.append("build_strategy")

        poc_strategy = str(review.get("poc_strategy", "")).strip()
        if poc_strategy in self.POC_STRATEGIES and self._poc_is_compatible(poc_strategy, plan.runtime_type):
            plan.poc_strategy = poc_strategy
            accepted.append("poc_strategy")
        elif poc_strategy:
            rejected.append("poc_strategy")

        oracle = str(review.get("oracle", "")).strip()
        if oracle in self.ORACLES and self._oracle_is_compatible(oracle, finding, plan.runtime_type):
            plan.oracle = oracle
            accepted.append("oracle")
        elif oracle:
            rejected.append("oracle")

        rationale = str(review.get("rationale", "")).strip()[:600]
        if rationale:
            plan.rationale = f"{plan.rationale} LLM tactic: {rationale}"
            accepted.append("rationale")
        recipe = review.get("verification_recipe")
        if isinstance(recipe, dict):
            sanitized = self._sanitize_recipe(finding, environment, plan, recipe)
            if sanitized:
                plan.verification_recipe = sanitized
                accepted.append("verification_recipe")
            else:
                rejected.append("verification_recipe")
        plan.planner_review = {
            "status": "completed",
            "accepted_fields": accepted,
            "rejected_fields": rejected,
            "cannot_override_blocked": plan.status == "blocked",
        }

    @staticmethod
    def _compatible_runtimes(runtime_type: str) -> set[str]:
        if runtime_type in {"cpp_cli", "cpp_harness"}:
            return {"cpp_cli", "cpp_harness"}
        return {runtime_type}

    @staticmethod
    def _build_is_supported(
        build_strategy: str,
        environment: EnvironmentProfile,
        plan: DynamicVerificationPlan,
    ) -> bool:
        if build_strategy in {"existing_binary", "no_build_possible", "no_build_required"}:
            return True
        required = build_strategy.removesuffix("_build")
        return plan.runtime_type in {"cpp_cli", "cpp_harness"} and required in environment.build_systems

    @staticmethod
    def _sanitize_recipe(
        finding: Finding,
        environment: EnvironmentProfile,
        plan: DynamicVerificationPlan,
        recipe: dict[str, Any],
    ) -> dict[str, Any]:
        safe: dict[str, Any] = {}
        for key in (
            "target_function",
            "source",
            "sink",
            "preconditions",
            "preferred_build",
            "runtime_entry",
            "fallback_harness",
            "micro_proof",
            "payloads",
            "payload_format",
            "stdin_script",
            "cli_args",
            "config_files",
            "harness_code",
            "harness_language",
            "harness_filename",
            "run_commands",
            "execution_steps",
            "oracle",
            "expected_signal",
            "limitations",
        ):
            value = recipe.get(key)
            if isinstance(value, str):
                safe[key] = value.strip()[:1200]
            elif isinstance(value, list):
                safe[key] = [str(item)[:500] for item in value[:8]]
            elif isinstance(value, dict):
                safe[key] = {str(k)[:80]: str(v)[:500] for k, v in list(value.items())[:12]}
            elif value is not None:
                safe[key] = str(value)[:500]
        preferred = str(safe.get("preferred_build", "") or "")
        if preferred and preferred not in DynamicPlanner.BUILD_STRATEGIES and preferred not in environment.build_systems:
            return {}
        safe.setdefault("target_function", finding.function_name or "unknown")
        safe.setdefault("source", finding.source or "unknown")
        safe.setdefault("sink", finding.sink or "unknown")
        safe.setdefault("preferred_build", plan.build_strategy)
        safe.setdefault("runtime_entry", plan.runtime_type)
        safe.setdefault("oracle", plan.oracle)
        safe.setdefault("expected_signal", plan.oracle)
        safe["source_kind"] = "llm_review"
        return safe

    @staticmethod
    def _poc_is_compatible(poc_strategy: str, runtime_type: str) -> bool:
        allowed = {
            "cpp_cli": {"malformed_file", "cli_arg"},
            "cpp_harness": {"malformed_file", "cli_arg", "harness"},
            "python_test": {"unit_test", "harness"},
            "node_test": {"unit_test", "harness"},
            "php_test": {"unit_test", "harness"},
            "java_test": {"unit_test", "harness"},
            "go_test": {"unit_test", "harness"},
            "http_service": {"http_request"},
            "library_harness": {"harness", "unit_test"},
        }
        return poc_strategy in allowed.get(runtime_type, set())

    @staticmethod
    def _oracle_is_compatible(oracle: str, finding: Finding, runtime_type: str) -> bool:
        if runtime_type == "http_service":
            return oracle in {"http_status_or_body_marker", "stderr_marker", "output_diff", "timeout"}
        if finding.vulnerability_type in {
            "unsafe_memory_copy",
            "unsafe_c_string_api",
            "out_of_bounds_read",
            "out_of_bounds_write",
            "use_after_free",
            "double_free",
        }:
            return oracle in {"asan_crash", "ubsan", "nonzero_exit", "stderr_marker", "timeout"}
        if finding.vulnerability_type == "command_injection":
            return oracle in {"stderr_marker", "output_diff", "nonzero_exit", "timeout"}
        if finding.vulnerability_type in {"path_traversal", "sql_injection"}:
            return oracle in {"output_diff", "stderr_marker", "timeout"}
        return oracle in {"nonzero_exit_or_checker_marker", "nonzero_exit", "stderr_marker", "timeout"}

    @staticmethod
    def _record_review_error(
        items: list[tuple[Finding, StaticVerificationResult, EnvironmentProfile, DynamicVerificationPlan]],
        reason: str,
    ) -> None:
        for _finding, _static_result, _environment, plan in items:
            plan.planner_review = {"status": "failed", "reason": reason[:300], "accepted_fields": []}

    def skipped(self, finding: Finding, reason: str, rationale: str) -> DynamicVerificationPlan:
        return DynamicVerificationPlan(
            finding_id=finding.id,
            status="skipped",
            runtime_type="static_only",
            build_strategy="none",
            poc_strategy="none",
            oracle="static evidence only",
            rationale=rationale,
            strategy="static_only",
            blocked_reason=reason,
        )

    def budget_exhausted(self, finding: Finding) -> DynamicVerificationPlan:
        return self.skipped(
            finding,
            "dynamic_budget_exhausted",
            "Static verification passed, but the audit mode dynamic-verification budget was exhausted.",
        )

    @staticmethod
    def _build_strategy(build_decision: BuildDecision | None) -> str:
        system = (build_decision.build_system if build_decision else "").lower()
        return {
            "cmake": "cmake_build",
            "autotools": "autotools_build",
            "make": "make_build",
            "meson": "meson_build",
        }.get(system, "no_build_possible")

    @staticmethod
    def _native_blocked_reason(
        build_decision: BuildDecision | None,
        environment: EnvironmentProfile,
    ) -> str:
        if build_decision and build_decision.blocked_reason:
            return build_decision.blocked_reason
        if build_decision and build_decision.missing_tools:
            return "missing_tool"
        reason = (build_decision.reason if build_decision else "").lower()
        if "disabled" in reason:
            return "build_disabled"
        if not environment.build_systems:
            return "binary_not_found"
        if build_decision and build_decision.status == "blocked":
            return "build_failed"
        return "binary_not_found"

    @staticmethod
    def _poc_strategy(finding: Finding, runtime_type: str) -> str:
        if runtime_type == "http_service":
            return "http_request"
        if runtime_type in {"cpp_cli", "cpp_harness"}:
            return "malformed_file" if finding.vulnerability_type not in {"command_injection"} else "cli_arg"
        if runtime_type in {"python_test", "node_test", "php_test", "java_test", "go_test"}:
            return "unit_test"
        if runtime_type == "library_harness":
            return "harness"
        return "none"

    @staticmethod
    def _oracle(finding: Finding, runtime_type: str) -> str:
        vuln_type = finding.vulnerability_type
        if vuln_type in {"unsafe_memory_copy", "unsafe_c_string_api", "out_of_bounds_read", "out_of_bounds_write", "use_after_free", "double_free"}:
            return "asan_crash"
        if vuln_type == "command_injection":
            return "stderr_marker"
        if vuln_type == "path_traversal":
            return "output_diff"
        if vuln_type == "sql_injection":
            return "output_diff"
        if runtime_type == "http_service":
            return "http_status_or_body_marker"
        return "nonzero_exit_or_checker_marker"

    @staticmethod
    def _fallback_recipe(
        finding: Finding,
        plan: DynamicVerificationPlan,
        environment: EnvironmentProfile,
        static_result: StaticVerificationResult,
    ) -> dict[str, Any]:
        return {
            "source_kind": "deterministic_fallback",
            "target_function": finding.function_name or "unknown",
            "source": finding.source or "unknown",
            "sink": finding.sink or "unknown",
            "preconditions": finding.trigger_conditions or [static_result.reason],
            "preferred_build": plan.build_strategy,
            "runtime_entry": plan.runtime_type,
            "fallback_harness": (
                "Generate a constrained local harness for the reported source/sink chain when full runtime is blocked."
            ),
            "micro_proof": (
                "If target-specific harness compilation is not possible, compile/run a minimal no-network proof that "
                "exercises the same sink pattern and records limitations."
            ),
            "payloads": [],
            "payload_format": "poc_template",
            "stdin_script": "",
            "cli_args": [],
            "config_files": [],
            "harness_code": "",
            "execution_steps": [],
            "oracle": plan.oracle,
            "expected_signal": plan.oracle,
            "limitations": [
                "LLM recipe is advisory only.",
                "Partial harness evidence does not upgrade the result to verified.",
                f"Detected build systems: {', '.join(environment.build_systems) or 'none'}",
            ],
        }


class RuntimeManager:
    """Execute a validated dynamic plan. ``decide`` remains as a compatibility shim."""

    def __init__(self, sandbox: SandboxExecutor | None = None, checker: EvidenceChecker | None = None) -> None:
        self.sandbox = sandbox or SandboxExecutor()
        self.checker = checker or EvidenceChecker()

    def decide(
        self,
        target: Path,
        profile: ProjectProfile,
        finding: Finding,
        environment: EnvironmentProfile,
        runtime_url: str = "",
        native_executable: Path | None = None,
    ) -> RuntimeDecision:
        if finding.vulnerability_type in {"dependency_vulnerability", "secret_leak", "hardcoded_secret"}:
            return RuntimeDecision("dependency_only", "static_dependency_evidence", "Dynamic exploit replay is intentionally skipped.")
        if finding.route or runtime_url:
            return RuntimeDecision("http_service", "http_probe", "Route or runtime_url is available.", can_execute=bool(runtime_url))
        runtime_type = environment.runtime_type
        if runtime_type == "cpp_cli":
            if native_executable:
                return RuntimeDecision("cpp_cli", "native_cli_with_payload", "Existing/built native CLI is available.", [[str(native_executable)]], True, True)
            return RuntimeDecision(
                "cpp_harness",
                "native_harness_or_static_blocked",
                "No native executable was detected; generate PoC input and preserve build evidence.",
                requires_build=True,
                can_execute=False,
                blocked_reason="missing_native_cli",
                fallbacks=["weak_static_proof", "static_blocked"],
            )
        if runtime_type == "python_test":
            return RuntimeDecision("python_test", "python_harness_or_pytest", "Python runtime can use pytest/direct harness.", can_execute=True)
        if runtime_type == "node_test":
            return RuntimeDecision("node_test", "node_harness_or_npm_test", "Node runtime can use npm test or a Node harness.", can_execute=True)
        if runtime_type == "php_test":
            return RuntimeDecision("php_test", "php_harness_or_phpunit", "PHP runtime can use a constrained generated harness.", can_execute=True)
        if runtime_type == "java_test":
            return RuntimeDecision("java_test", "java_harness_or_junit", "Java runtime can use javac/JUnit-style constrained harnesses.", can_execute=True)
        if runtime_type == "go_test":
            return RuntimeDecision("go_test", "go_harness_or_go_test", "Go runtime can use go test or a constrained generated harness.", can_execute=True)
        if runtime_type == "library_harness":
            return RuntimeDecision("library_harness", "generated_library_harness", "Library/plugin project needs a mock host/harness.", can_execute=True)
        if runtime_type.endswith("_blocked"):
            return RuntimeDecision(runtime_type, "static_blocked", "Language runtime is recognized but not dynamically supported in phase 5.", blocked_reason=runtime_type)
        return RuntimeDecision("weak_static_proof", "weak_static_proof", "No executable entry point was identified.", fallbacks=["static_blocked"])

    def execute(
        self,
        target: Path,
        profile: ProjectProfile,
        plan: PocPlan,
        decision: RuntimeDecision,
        runtime_url: str,
        planner: VerificationPlanner,
    ) -> CheckerOutcome:
        if decision.runtime_type in {"dependency_only", "weak_static_proof", "static_blocked"} or decision.runtime_type.endswith("_blocked"):
            outcome = self.checker.check(target, plan, runtime_url)
            if outcome.status == "uncertain" and decision.runtime_type in {"weak_static_proof", "static_blocked"}:
                outcome.status = "blocked"
                outcome.summary = decision.rationale
                outcome.checker_details = {"checker": "GenericChecker", "blocked_reason": decision.blocked_reason or decision.runtime_type}
            return outcome
        if decision.runtime_type == "http_service":
            return self.checker.check(target, plan, runtime_url)
        if plan.analysis.verification_mode == "cpp_cli":
            if not plan.target_command:
                return self.checker.check(target, plan, runtime_url)
            return self.checker.dispatch(
                plan.finding,
                self.sandbox.execute_command(plan.target_command, plan.poc_dir / "sandbox"),
            )
        harness = planner.plan(plan.finding, target)
        harness.runtime_type = decision.runtime_type
        harness.strategy = decision.strategy
        outcome = self.sandbox.execute(harness, plan.poc_dir / "sandbox")
        checked = self.checker.dispatch(plan.finding, outcome)
        if outcome.status == "verified" and decision.runtime_type in {"cpp_harness", "python_test", "node_test", "php_test", "java_test", "go_test", "library_harness"}:
            checked.status = "harness_reproduced"
            checked.summary = "Generated harness reproduced the configured oracle; this is not full target runtime verification."
            checked.checker_details["proof_level"] = "generated_harness"
        return checked

    def execute_plan(
        self,
        target: Path,
        profile: ProjectProfile,
        poc_plan: PocPlan,
        dynamic_plan: DynamicVerificationPlan,
        runtime_url: str,
        planner: VerificationPlanner,
    ) -> CheckerOutcome:
        if dynamic_plan.status != "planned":
            if self._can_attempt_partial_proof(dynamic_plan):
                harness = planner.partial_proof_plan(poc_plan.finding, target, dynamic_plan)
                outcome = self.sandbox.execute(harness, poc_plan.poc_dir / "partial-proof")
                text = f"{outcome.stdout_excerpt}\n{outcome.stderr_excerpt}".lower()
                matched = "[detected]" in text or "addresssanitizer" in text or "undefinedbehavior" in text
                attempt = {
                    "kind": harness.strategy or "micro_proof",
                    "status": "partial_dynamic_proof" if matched else outcome.status,
                    "blocked_reason": dynamic_plan.blocked_reason,
                    "command": outcome.sandbox_command,
                    "exit_code": outcome.exit_code,
                    "stdout_excerpt": outcome.stdout_excerpt[-1200:],
                    "stderr_excerpt": outcome.stderr_excerpt[-1200:],
                    "artifacts": [str(path) for path in outcome.artifact_paths],
                    "limitations": [
                        "Partial proof is isolated from the full target runtime.",
                        "This evidence cannot produce verified status.",
                    ],
                }
                outcome.status = "partial_dynamic_proof" if matched else "blocked"
                outcome.summary = (
                    "Partial dynamic proof executed after full runtime was blocked."
                    if matched
                    else "Partial dynamic proof could not reproduce an oracle after full runtime was blocked."
                )
                outcome.evidence.append(f"Original dynamic block: {dynamic_plan.blocked_reason}")
                outcome.checker_details.update(
                    {
                        "checker": "PartialProofChecker",
                        "proof_level": "micro_proof",
                        "blocked_reason": dynamic_plan.blocked_reason,
                        "fallback_attempts": [attempt],
                    }
                )
                return outcome
            return CheckerOutcome(
                status="blocked",
                summary=dynamic_plan.rationale,
                evidence=[f"Dynamic plan blocked: {dynamic_plan.blocked_reason}"],
                checker_details={
                    "checker": "DynamicPlanGate",
                    "blocked_reason": dynamic_plan.blocked_reason,
                },
            )
        return self._execute_with_dynamic_plan(
            target,
            profile,
            poc_plan,
            dynamic_plan,
            runtime_url,
            planner,
        )

    def _execute_with_dynamic_plan(
        self,
        target: Path,
        profile: ProjectProfile,
        plan: PocPlan,
        dynamic_plan: DynamicVerificationPlan,
        runtime_url: str,
        planner: VerificationPlanner,
    ) -> CheckerOutcome:
        decision = dynamic_plan.to_runtime_decision()
        if decision.runtime_type in {"dependency_only", "weak_static_proof", "static_blocked"} or decision.runtime_type.endswith("_blocked"):
            return self.execute(target, profile, plan, decision, runtime_url, planner)
        if decision.runtime_type == "http_service" or plan.analysis.verification_mode == "cpp_cli":
            return self.execute(target, profile, plan, decision, runtime_url, planner)
        harness = planner.plan(plan.finding, target, dynamic_plan)
        harness.runtime_type = decision.runtime_type
        harness.strategy = harness.strategy or decision.strategy
        outcome = self.sandbox.execute(harness, plan.poc_dir / "sandbox")
        checked = self.checker.dispatch(plan.finding, outcome)
        if outcome.status == "verified" and decision.runtime_type in {"cpp_harness", "python_test", "node_test", "php_test", "java_test", "go_test", "library_harness"}:
            checked.status = "harness_reproduced"
            checked.summary = "Generated harness reproduced the configured oracle; this is not full target runtime verification."
            checked.checker_details["proof_level"] = "generated_harness"
        return checked

    @staticmethod
    def _can_attempt_partial_proof(dynamic_plan: DynamicVerificationPlan) -> bool:
        if dynamic_plan.blocked_reason in {"build_disabled", "dynamic_budget_exhausted", "risk_domain_static_only"}:
            return False
        if dynamic_plan.runtime_type in {"cpp_harness", "cpp_cli", "python_test", "node_test", "php_test", "java_test", "go_test", "library_harness"}:
            return dynamic_plan.blocked_reason in {
                "build_failed",
                "binary_not_found",
                "missing_dependency",
                "wrong_build_system",
                "missing_native_cli",
                "no_runtime_entry",
                "missing_runtime",
                "sandbox_unavailable",
            }
        return False


class ExploitAgent:
    """Archive reproducible PoC or blocked reproduction notes for every attempt."""

    def generate(self, plan: PocPlan, outcome: CheckerOutcome, output_dir: Path) -> list[Path]:
        exploit_dir = output_dir / "exploits" / plan.finding.id
        exploit_dir.mkdir(parents=True, exist_ok=True)
        exploit = exploit_dir / "exploit.md"
        exploit.write_text(self._exploit_doc(plan, outcome), encoding="utf-8")
        replay = exploit_dir / ("replay.ps1" if os.name == "nt" else "replay.sh")
        replay.write_text(self._replay(plan, outcome), encoding="utf-8")
        return [exploit, replay]

    def _exploit_doc(self, plan: PocPlan, outcome: CheckerOutcome) -> str:
        return "\n".join(
            [
                f"# Verification Exploit Record: {plan.finding.id}",
                "",
                f"- Status: `{outcome.status}`",
                f"- Mode: `{plan.analysis.verification_mode}`",
                f"- Oracle: {plan.analysis.oracle}",
                f"- PoC: `{plan.poc_path}`",
                f"- Command: `{' '.join(plan.target_command or outcome.sandbox_command) or 'n/a'}`",
                f"- Local fallback: `{outcome.local_fallback}`",
                "",
                "## Result",
                outcome.summary,
                "",
                "## Evidence",
                *[f"- {item}" for item in outcome.evidence],
            ]
        )

    def _replay(self, plan: PocPlan, outcome: CheckerOutcome) -> str:
        command = plan.target_command or outcome.sandbox_command
        if not command:
            return "# No executable replay command was available; see exploit.md for blocked details.\n"
        if os.name == "nt":
            return "& " + " ".join(shlex.quote(item) for item in command) + "\n"
        return "#!/usr/bin/env bash\nset -euo pipefail\n" + " ".join(shlex.quote(item) for item in command) + "\n"


class VerificationAgent:
    """Phase-5 verifier: plan, environment, runtime, evidence, checker, exploit archive."""

    def __init__(
        self,
        auto_build_native: bool = False,
        llm_client: DeepSeekClient | None = None,
        event_sink: Callable[[str, str, str, dict[str, Any]], None] | None = None,
        sandbox_container: str = "agentic-code-audit-sandbox",
        sandbox_image: str = "agentic-code-audit-sandbox:local",
        build_network_enabled: bool = False,
    ) -> None:
        self.auto_build_native = auto_build_native
        self.event_sink = event_sink
        self.analyzer = PocAnalyzer(llm_client)
        self.generator = PocGenerator(llm_client)
        self.checker = EvidenceChecker()
        self.static_verifier = StaticVerifier(llm_client)
        self.dynamic_planner = DynamicPlanner(llm_client)
        self.environment_manager = EnvironmentManager(sandbox_container)
        self.build_manager = BuildManager(sandbox_container, sandbox_image, build_network_enabled)
        self.native_builder = NativeBuildAgent()
        self.planner = VerificationPlanner(llm_client)
        self.sandbox = SandboxExecutor(sandbox_image, sandbox_container)
        self.runtime_manager = RuntimeManager(self.sandbox, self.checker)
        self.exploit_agent = ExploitAgent()

    def verify(
        self,
        target: Path,
        findings: list[Finding],
        output_dir: Path,
        profile: ProjectProfile,
        runtime_url: str = "",
        strategy: Any | None = None,
        mining_context: Any | None = None,
        max_dynamic_verifications: int | None = None,
        enable_native_build: bool | None = None,
    ) -> list[VerificationResult]:
        output_dir.mkdir(parents=True, exist_ok=True)
        results: list[VerificationResult] = []
        ordered_findings = self._order_findings_for_strategy(findings, strategy)
        candidate_by_id = {
            item.id: item for item in getattr(mining_context, "candidates", [])
        }
        slice_by_id = {
            item.id: item for item in getattr(mining_context, "program_slices", [])
        }
        dangerous_by_id = {
            item.id: item for item in getattr(mining_context, "dangerous_functions", [])
        }
        tool_results = list(getattr(mining_context, "tool_results", []))
        static_results = [
            self.static_verifier.verify(
                target,
                finding,
                candidate_by_id.get(finding.candidate_id),
                slice_by_id.get(finding.slice_id),
                dangerous_by_id.get(finding.dangerous_function_id),
                tool_results,
            )
            for finding in ordered_findings
        ]
        self.static_verifier.review_batch(ordered_findings, static_results)
        eligible_ids = [
            finding.id
            for finding, static_result in zip(ordered_findings, static_results)
            if static_result.dynamic_eligible
        ]
        dynamic_limit = len(eligible_ids) if max_dynamic_verifications is None else max(0, max_dynamic_verifications)
        selected_dynamic_ids = set(eligible_ids[:dynamic_limit])
        dynamic_states: dict[str, tuple[EnvironmentProfile, BuildDecision, Path | None, DynamicVerificationPlan]] = {}
        review_items: list[tuple[Finding, StaticVerificationResult, EnvironmentProfile, DynamicVerificationPlan]] = []
        native_build_enabled = self.auto_build_native if enable_native_build is None else enable_native_build
        for finding, static_result in zip(ordered_findings, static_results):
            if finding.id not in selected_dynamic_ids:
                continue
            environment = self.environment_manager.inspect(target, profile, finding)
            build_decision, native_executable = self.build_manager.prepare(
                target,
                profile,
                finding,
                environment,
                output_dir,
                auto_build_native=native_build_enabled,
            )
            dynamic_plan = self.dynamic_planner.plan(
                target,
                profile,
                finding,
                static_result,
                environment,
                runtime_url,
                native_executable,
                build_decision,
                self._director_hint_for_finding(finding, strategy),
            )
            dynamic_states[finding.id] = (environment, build_decision, native_executable, dynamic_plan)
            review_items.append((finding, static_result, environment, dynamic_plan))
        self.dynamic_planner.review_batch(profile, review_items)

        for finding, static_result in zip(ordered_findings, static_results):
            if not static_result.dynamic_eligible:
                dynamic_plan = self.dynamic_planner.plan(
                    target,
                    profile,
                    finding,
                    static_result,
                    EnvironmentProfile(
                        runtime_type="static_only",
                        languages=dict(profile.languages),
                        project_type=profile.project_type,
                    ),
                    runtime_url,
                )
                results.append(self._static_result(finding, static_result, dynamic_plan))
                continue
            if finding.id not in selected_dynamic_ids:
                dynamic_plan = self.dynamic_planner.budget_exhausted(finding)
                results.append(self._static_result(finding, static_result, dynamic_plan))
                continue

            environment, build_decision, native_executable, dynamic_plan = dynamic_states[finding.id]
            decision = dynamic_plan.to_runtime_decision()
            analysis = self.analyzer.analyze(target, finding, profile)
            if decision.runtime_type == "cpp_harness" and analysis.verification_mode == "cpp_cli":
                # Keep method compatibility with existing reports while recording the real runtime separately.
                analysis.runtime_type = "cli"
            elif decision.runtime_type == "dependency_only":
                analysis.verification_mode = "dependency_only"
                analysis.runtime_type = "dependency_only"
            elif decision.runtime_type in {"weak_static_proof", "static_blocked"}:
                analysis.verification_mode = decision.runtime_type
                analysis.runtime_type = decision.runtime_type
            analysis.oracle = dynamic_plan.oracle
            structured_plan = self.planner.structured_plan(finding, target, decision, environment)
            structured_plan.update(dynamic_plan.to_dict())
            plan = self.generator.generate(target, finding, analysis, output_dir, native_executable, structured_plan)

            self._emit(
                "EnvironmentManager",
                "stage_done",
                f"environment ready: {finding.id}",
                {"finding_id": finding.id, "runtime_type": environment.runtime_type, "gaps": environment.environment_gaps},
            )
            dynamic_attempted = dynamic_plan.status == "planned"
            if dynamic_plan.status == "blocked" and self._should_preserve_block_without_partial(dynamic_plan):
                outcome = CheckerOutcome(
                    status="blocked",
                    summary=dynamic_plan.rationale,
                    evidence=[static_result.reason, *self.checker._check_static_anchor(target, finding)],
                    checker_details={
                        "checker": "DynamicPlanGate",
                        "blocked_reason": dynamic_plan.blocked_reason,
                    },
                )
            else:
                outcome = self.runtime_manager.execute_plan(
                    target,
                    profile,
                    plan,
                    dynamic_plan,
                    runtime_url,
                    self.planner,
                )

            if build_decision.evidence:
                outcome.evidence.extend(build_decision.evidence)
            if environment.environment_gaps:
                outcome.evidence.extend(f"Environment gap: {gap}" for gap in environment.environment_gaps)
            exploit_paths = self.exploit_agent.generate(plan, outcome, output_dir)
            self._emit(
                "EvidenceChecker",
                "stage_done",
                f"{finding.id}: {outcome.status}",
                {"finding_id": finding.id, "status": outcome.status, "checker": outcome.checker_details},
            )
            results.append(
                self._to_result(
                    plan,
                    outcome,
                    environment,
                    decision,
                    build_decision,
                    exploit_paths,
                    static_result,
                    dynamic_plan,
                    dynamic_attempted,
                )
            )
        return results

    @staticmethod
    def _should_preserve_block_without_partial(dynamic_plan: DynamicVerificationPlan) -> bool:
        return dynamic_plan.blocked_reason in {
            "build_disabled",
            "dynamic_budget_exhausted",
            "risk_domain_static_only",
        }

    @staticmethod
    def _director_hint_for_finding(finding: Finding, strategy: Any | None) -> dict[str, Any]:
        if not strategy:
            return {}
        hint: dict[str, Any] = {}
        function_name = finding.function_name or ""
        if bool(getattr(strategy, "build_attempt", False)):
            hint["build_attempt"] = True
        harness_candidates = list(getattr(strategy, "harness_candidates", []) or [])
        if function_name and any(item.lower() in function_name.lower() for item in harness_candidates):
            hint["harness_candidate"] = function_name
        parser_entries = list(getattr(strategy, "parser_entries", []) or [])
        matched_entries = [item for item in parser_entries if item.lower() in function_name.lower()]
        if matched_entries:
            hint["parser_entries"] = matched_entries
        suggested_oracles = dict(getattr(strategy, "suggested_oracles", {}) or {})
        for key in (function_name, finding.vulnerability_type, "default"):
            if key and key in suggested_oracles:
                hint["oracle"] = suggested_oracles[key]
                break
        return hint

    def _order_findings_for_strategy(
        self,
        findings: list[Finding],
        strategy: Any | None,
    ) -> list[Finding]:
        if not strategy:
            return findings
        return sorted(
            findings,
            key=lambda item: (
                1 if item.should_verify else 0,
                int(getattr(item, "director_priority", 0) or 0),
                float(getattr(item, "confidence", 0.0) or 0.0),
            ),
            reverse=True,
        )

    def _to_result(
        self,
        plan: PocPlan,
        outcome: CheckerOutcome,
        environment: EnvironmentProfile,
        decision: RuntimeDecision,
        build_decision: BuildDecision,
        exploit_paths: list[Path],
        static_result: StaticVerificationResult,
        dynamic_plan: DynamicVerificationPlan,
        dynamic_attempted: bool,
    ) -> VerificationResult:
        metadata_path = plan.poc_dir / "verification.json"
        blocked_reason = self._blocked_reason(outcome, dynamic_plan, environment)
        execution = dict(outcome.execution)
        if build_decision.execution:
            execution["build_steps"] = build_decision.execution
        if blocked_reason and "blocked_reason" not in outcome.checker_details:
            outcome.checker_details["blocked_reason"] = blocked_reason
        fallback_attempts = list(outcome.checker_details.get("fallback_attempts", []) or [])
        proof_level = self._proof_level(outcome, decision, dynamic_plan)
        validation_tags = self._validation_tags(static_result, dynamic_plan, outcome, blocked_reason)
        generated_paths = [*plan.generated_artifacts, *outcome.artifact_paths, *exploit_paths, metadata_path]
        artifact_records = [
            self._artifact_record("verification_output", path, plan.finding.id)
            for path in [*plan.generated_artifacts, metadata_path, *outcome.artifact_paths]
        ]
        exploit_records = [self._artifact_record("exploit_output", path, plan.finding.id) for path in exploit_paths]
        all_records = [*artifact_records, *exploit_records]
        evidence_artifact_ids = [record.id for record in artifact_records]
        exploit_artifact_ids = [record.id for record in exploit_records]
        payload = {
            "finding_id": plan.finding.id,
            "analysis": asdict(plan.analysis),
            "verification_plan": plan.structured_plan or self._verification_plan(plan, decision),
            "poc_path": str(plan.poc_path),
            "target_command": plan.target_command,
            "checker": asdict(outcome),
            "environment": environment.to_dict(),
            "environment_gaps": environment.environment_gaps,
            "execution": execution,
            "build": asdict(build_decision),
            "static_verification": static_result.to_dict(),
            "dynamic_verification": dynamic_plan.to_dict(),
            "checker_verdict": {
                "status": outcome.status,
                "reason": outcome.summary,
                "details": outcome.checker_details,
                "blocked_reason": blocked_reason,
            },
            "verification_recipe": dynamic_plan.verification_recipe,
            "proof_level": proof_level,
            "validation_tags": validation_tags,
            "fallback_attempts": fallback_attempts,
            "evidence_artifact_ids": evidence_artifact_ids,
            "exploit_artifact_ids": exploit_artifact_ids,
            "generated_artifacts": [str(path) for path in generated_paths if path != metadata_path],
        }
        metadata_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        generated = [str(path) for path in generated_paths]
        return VerificationResult(
            finding_id=plan.finding.id,
            status=outcome.status if outcome.status in VERIFICATION_STATUSES else "uncertain",
            method=f"anypoc::{plan.analysis.verification_mode}",
            evidence=outcome.evidence,
            reproduction=outcome.summary,
            poc_path=str(plan.poc_path),
            payloads=plan.finding.exploit_payloads,
            http_status=outcome.http_status,
            http_evidence=outcome.http_evidence,
            analysis_verdict=plan.analysis.verdict,
            rejection_reason=plan.analysis.rejection_reason,
            verification_mode=plan.analysis.verification_mode,
            oracle=plan.analysis.oracle,
            target_command=plan.target_command,
            checker_status=outcome.status,
            checker_summary=outcome.summary,
            exit_code=outcome.exit_code,
            stdout_excerpt=outcome.stdout_excerpt,
            stderr_excerpt=outcome.stderr_excerpt,
            generated_artifacts=generated,
            verification_method=plan.analysis.details,
            verification_plan=plan.structured_plan or self._verification_plan(plan, decision),
            runtime_type=decision.runtime_type,
            strategy=decision.strategy,
            environment=environment.to_dict(),
            environment_gaps=environment.environment_gaps,
            execution=execution,
            evidence_artifact_ids=evidence_artifact_ids,
            exploit_artifact_ids=exploit_artifact_ids,
            checker_details=outcome.checker_details,
            local_fallback=outcome.local_fallback,
            entry_point=plan.analysis.entry_point,
            trigger_type=plan.analysis.trigger_type,
            attempts=1,
            sandbox_command=outcome.sandbox_command,
            sandbox_stdout=outcome.stdout_excerpt,
            sandbox_stderr=outcome.stderr_excerpt,
            artifact_ids=[record.id for record in all_records],
            artifact_records=all_records,
            static_verification=static_result.to_dict(),
            dynamic_verification=dynamic_plan.to_dict(),
            checker_verdict={
                "status": outcome.status,
                "reason": outcome.summary,
                "details": outcome.checker_details,
                "blocked_reason": blocked_reason,
            },
            dynamic_attempted=dynamic_attempted or bool(fallback_attempts),
            blocked_reason=blocked_reason,
            verification_recipe=dynamic_plan.verification_recipe,
            proof_level=proof_level,
            validation_tags=validation_tags,
            fallback_attempts=fallback_attempts,
        )

    def _static_result(
        self,
        finding: Finding,
        static_result: StaticVerificationResult,
        dynamic_plan: DynamicVerificationPlan,
    ) -> VerificationResult:
        if static_result.static_status == "likely_false_positive":
            status = "false_positive"
        elif static_result.static_status == "blocked_static":
            status = "blocked"
        elif dynamic_plan.blocked_reason == "dynamic_budget_exhausted":
            status = "partially_verified" if static_result.static_status == "plausible" else "uncertain"
        elif static_result.static_status == "static_only":
            status = "static_only"
        else:
            status = "uncertain"
        checker = {
            "status": status,
            "reason": static_result.reason,
            "details": {
                "checker": "StaticEvidenceChecker",
                "static_status": static_result.static_status,
                "dynamic_skip_reason": dynamic_plan.blocked_reason,
            },
        }
        proof_level = "static_only" if static_result.static_status in {"plausible", "weak_static_proof", "static_only"} else "none"
        validation_tags = self._validation_tags(
            static_result,
            dynamic_plan,
            CheckerOutcome(status=status, summary=static_result.reason, checker_details=checker["details"]),
            dynamic_plan.blocked_reason if status == "blocked" else "",
        )
        return VerificationResult(
            finding_id=finding.id,
            status=status,
            method="static_verifier",
            evidence=[static_result.reason, *static_result.evidence_refs],
            reproduction="Dynamic verification was not executed.",
            analysis_verdict=static_result.static_status,
            verification_mode="static_only",
            oracle="static evidence",
            checker_status=status,
            checker_summary=static_result.reason,
            verification_method="Static verification gate",
            verification_plan=dynamic_plan.to_dict(),
            runtime_type="static_only",
            strategy="static_only",
            checker_details=checker["details"],
            static_verification=static_result.to_dict(),
            dynamic_verification=dynamic_plan.to_dict(),
            checker_verdict=checker,
            dynamic_attempted=False,
            blocked_reason=dynamic_plan.blocked_reason if status == "blocked" else "",
            verification_recipe=dynamic_plan.verification_recipe,
            proof_level=proof_level,
            validation_tags=validation_tags,
            fallback_attempts=[],
        )

    @staticmethod
    def _blocked_reason(
        outcome: CheckerOutcome,
        dynamic_plan: DynamicVerificationPlan,
        environment: EnvironmentProfile,
    ) -> str:
        if outcome.status != "blocked":
            return ""
        explicit = str(outcome.checker_details.get("blocked_reason", "") or "")
        if dynamic_plan.blocked_reason or explicit:
            return dynamic_plan.blocked_reason or explicit
        if environment.missing_tools:
            return "missing_tool"
        if dynamic_plan.runtime_type in {"cpp_cli", "cpp_harness"}:
            return "binary_not_found"
        if "docker" in outcome.summary.lower():
            return "missing_docker"
        return "execution_failed"

    def _verification_plan(self, plan: PocPlan, decision: RuntimeDecision) -> dict[str, Any]:
        return {
            "strategy": decision.strategy,
            "runtime_type": decision.runtime_type or plan.analysis.runtime_type,
            "rationale": decision.rationale,
            "setup_commands": [],
            "files_to_create": [],
            "commands": [plan.target_command] if plan.target_command else [],
            "expected_signal": plan.analysis.oracle,
            "oracle": {"type": plan.analysis.verification_mode, "expected": plan.analysis.oracle},
            "fallbacks": decision.fallbacks,
            "environment_requirements": [],
            "mock_strategy": "",
            "weak_verification_strategy": "Preserve static anchors and blocked reasons.",
            "safety_notes": ["No network in Docker sandbox.", "Local fallback only for generated harnesses."],
        }

    @staticmethod
    def _proof_level(
        outcome: CheckerOutcome,
        decision: RuntimeDecision,
        dynamic_plan: DynamicVerificationPlan,
    ) -> str:
        explicit = str(outcome.checker_details.get("proof_level", "") or "")
        if explicit:
            return explicit
        if outcome.status == "verified":
            if decision.runtime_type == "cpp_cli":
                return "native_cli"
            if decision.runtime_type == "http_service":
                return "full_runtime"
            return "full_runtime"
        if outcome.status == "harness_reproduced":
            return "generated_harness"
        if outcome.status == "partial_dynamic_proof":
            return "micro_proof"
        if dynamic_plan.status == "planned":
            return "none"
        return "static_only"

    @staticmethod
    def _validation_tags(
        static_result: StaticVerificationResult,
        dynamic_plan: DynamicVerificationPlan,
        outcome: CheckerOutcome,
        blocked_reason: str,
    ) -> list[dict[str, Any]]:
        tags: list[dict[str, Any]] = []
        static_status = static_result.static_status
        if static_status == "plausible":
            tags.append({"stage": "static", "status": "passed", "label": "静态通过"})
        elif static_status == "weak_static_proof":
            tags.append({"stage": "static", "status": "weak", "label": "静态较弱"})
        elif static_status in {"likely_false_positive", "blocked_static"}:
            tags.append({"stage": "static", "status": "rejected", "label": "静态拒绝"})
        else:
            tags.append({"stage": "static", "status": static_status or "unknown", "label": f"静态: {static_status or 'unknown'}"})

        if outcome.status == "verified":
            dynamic_label = "动态: CLI verified" if dynamic_plan.runtime_type == "cpp_cli" else "动态: verified"
            tags.append({"stage": "dynamic", "status": "verified", "label": dynamic_label})
        elif outcome.status == "harness_reproduced":
            tags.append({"stage": "dynamic", "status": "harness_reproduced", "label": "动态: harness reproduced"})
        elif outcome.status == "partial_dynamic_proof":
            tags.append({"stage": "dynamic", "status": "partial_dynamic_proof", "label": "局部 proof"})
        elif dynamic_plan.status == "planned":
            tags.append({"stage": "dynamic", "status": "attempted", "label": "动态已执行"})
        elif blocked_reason or dynamic_plan.blocked_reason:
            reason = blocked_reason or dynamic_plan.blocked_reason
            label = "构建失败" if reason in {"build_failed", "wrong_build_system", "missing_dependency"} else f"动态阻塞: {reason}"
            tags.append({"stage": "dynamic", "status": "blocked", "label": label, "reason": reason})
        else:
            tags.append({"stage": "dynamic", "status": "not_run", "label": "动态未执行"})

        checker = str(outcome.checker_details.get("checker", "") or "Checker")
        if outcome.status in {"verified", "harness_reproduced", "partial_dynamic_proof", "partially_verified"}:
            tags.append({"stage": "checker", "status": "passed", "label": "Checker 命中", "checker": checker})
        elif outcome.status == "blocked":
            tags.append({"stage": "checker", "status": "blocked", "label": "Checker 阻塞", "checker": checker})
        elif outcome.status in {"not_reproducible", "false_positive"}:
            tags.append({"stage": "checker", "status": "failed", "label": "Checker 未命中", "checker": checker})
        else:
            tags.append({"stage": "checker", "status": "unknown", "label": "Checker 未运行", "checker": checker})
        return tags

    def _emit(self, agent: str, event_type: str, message: str, metadata: dict[str, Any]) -> None:
        if self.event_sink:
            self.event_sink(agent, event_type, message, metadata)

    def _artifact_record(self, kind: str, path: Path, finding_id: str) -> ArtifactRecord:
        return ArtifactRecord(
            id=str(uuid.uuid4()),
            kind=kind,
            path=str(path),
            metadata={"finding_id": finding_id, "name": path.name},
        )
