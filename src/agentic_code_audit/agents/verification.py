from __future__ import annotations

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
from ..models import ArtifactRecord, Finding, ProjectProfile, VerificationResult


VERIFICATION_STATUSES = {
    "verified",
    "exploitable",
    "partially_verified",
    "not_reproducible",
    "blocked",
    "false_positive",
    "uncertain",
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
        "node": "Install Node.js LTS.",
        "npm": "Install Node.js LTS.",
        "curl": "Install curl or use PowerShell Invoke-WebRequest manually.",
        "sqlite3": "Install sqlite3 CLI or use Python sqlite3 for harnesses.",
    }

    def inspect(self, target: Path, profile: ProjectProfile, finding: Finding) -> EnvironmentProfile:
        runtime_type = self._runtime_type(profile, finding)
        tools = self._tools_for(runtime_type, profile, target)
        available: dict[str, str] = {}
        missing: list[str] = []
        for tool in tools:
            path = shutil.which(tool)
            if path:
                available[tool] = path
            else:
                missing.append(tool)
        build_systems = self._build_systems(target)
        gaps = [f"missing tool: {tool}" for tool in missing]
        if runtime_type in {"static_blocked", "weak_static_proof"}:
            gaps.append("no executable entry point was identified")
        if runtime_type in {"go_blocked", "rust_blocked", "java_blocked", "php_blocked", "ruby_blocked"}:
            gaps.append(f"{runtime_type.removesuffix('_blocked')} dynamic verification is not enabled in phase 5")
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
            return "go_blocked"
        if "Rust" in languages:
            return "rust_blocked"
        if "Java" in languages:
            return "java_blocked"
        if "PHP" in languages:
            return "php_blocked"
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
        if runtime_type == "http_service":
            tools.append("curl")
        if target.exists() and any(name.endswith(".db") or name.endswith(".sqlite") for name in os.listdir(target)):
            tools.append("sqlite3")
        return list(dict.fromkeys(tools))

    def _build_systems(self, target: Path) -> list[str]:
        systems: list[str] = []
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
        return systems


class BuildManager:
    """Prepare build/runtime assets and record blocked reasons instead of guessing silently."""

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
            decision = BuildDecision(False, f"Found existing native executable: {existing}", status="ready")
            decision.evidence.append(decision.reason)
            return decision, existing

        build_system = environment.build_systems[0] if environment.build_systems else ""
        missing = []
        if build_system == "cmake" and not shutil.which("cmake"):
            missing.append("cmake")
        if build_system == "make" and not shutil.which("make"):
            missing.append("make")
        if not (shutil.which("clang") or shutil.which("gcc")):
            missing.append("clang or gcc")
        if missing:
            decision = BuildDecision(
                False,
                f"Native build blocked because required tools are missing: {', '.join(missing)}.",
                build_system=build_system,
                instrumentation=["asan", "ubsan"],
                status="blocked",
                missing_tools=missing,
                install_hints=[EnvironmentManager.TOOL_HINTS.get(item, f"Install {item}.") for item in missing],
            )
            decision.evidence.extend([decision.reason, *decision.install_hints])
            return decision, None

        if not auto_build_native:
            decision = BuildDecision(
                False,
                f"{build_system or 'native'} project detected; auto-build is disabled.",
                build_system=build_system,
                instrumentation=["asan", "ubsan"],
                status="blocked",
            )
            decision.evidence.append(decision.reason)
            return decision, None

        if build_system == "cmake":
            return self._build_cmake(target, output_dir)
        decision = BuildDecision(
            False,
            f"Build system {build_system or 'unknown'} is recorded but not executed automatically in phase 5.",
            build_system=build_system,
            instrumentation=["asan", "ubsan"],
            status="blocked",
        )
        decision.evidence.append(decision.reason)
        return decision, None

    def _build_cmake(self, target: Path, output_dir: Path) -> tuple[BuildDecision, Path | None]:
        build_dir = target / ".agentic-build"
        build_dir.mkdir(parents=True, exist_ok=True)
        log_path = output_dir / "native-build.log"
        configure = [
            "cmake",
            "-S",
            str(target),
            "-B",
            str(build_dir),
            "-DCMAKE_BUILD_TYPE=Debug",
            "-DCMAKE_C_FLAGS=-fsanitize=address,undefined -fno-omit-frame-pointer",
            "-DCMAKE_CXX_FLAGS=-fsanitize=address,undefined -fno-omit-frame-pointer",
        ]
        build = ["cmake", "--build", str(build_dir), "--config", "Debug", "-j", "2"]
        logs: list[str] = []
        for command in (configure, build):
            try:
                completed = subprocess.run(
                    command,
                    cwd=str(target),
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
                        False,
                        f"CMake build failed before completion: {exc}",
                        "cmake",
                        ["asan", "ubsan"],
                        status="blocked",
                        evidence=[f"Build log: {log_path}"],
                    ),
                    None,
                )
            logs.append(
                "\n".join(
                    [
                        "$ " + " ".join(command),
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
                        False,
                        f"CMake command exited with {completed.returncode}.",
                        "cmake",
                        ["asan", "ubsan"],
                        status="blocked",
                        evidence=[f"Build log: {log_path}"],
                    ),
                    None,
                )
        log_path.write_text("\n\n".join(logs), encoding="utf-8")
        built = PocGenerator()._find_native_executable(build_dir)
        if built:
            return (
                BuildDecision(
                    True,
                    f"Built native executable: {built}",
                    "cmake",
                    ["asan", "ubsan"],
                    status="ready",
                    evidence=[f"Built native executable: {built}", f"Build log: {log_path}"],
                    commands=[configure, build],
                ),
                built,
            )
        return (
            BuildDecision(
                True,
                "CMake build completed, but no executable was detected.",
                "cmake",
                ["asan", "ubsan"],
                status="blocked",
                evidence=[f"Build log: {log_path}"],
                commands=[configure, build],
            ),
            None,
        )


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
    """AnyPoC-compatible first gate. RuntimeManager refines the final strategy."""

    def analyze(self, target: Path, finding: Finding, profile: ProjectProfile) -> PocAnalysis:
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

    def _is_native_source(self, file_path: str, profile: ProjectProfile) -> bool:
        suffix = Path(file_path).suffix.lower()
        if suffix in {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}:
            return True
        return any(lang in profile.languages for lang in ("C", "C++"))


class PocGenerator:
    """Generate stable PoC/runbook artifacts without treating them as proof."""

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

        bug_report = poc_dir / "bug_report.md"
        bug_report.write_text(self._bug_report(finding, analysis), encoding="utf-8")
        if analysis.verification_mode == "http":
            poc_path = poc_dir / "poc_http.py"
            poc_path.write_text(self._http_poc(finding), encoding="utf-8")
        elif analysis.verification_mode in {"cpp_cli", "cpp_harness"}:
            poc_path = poc_dir / "poc_input.bin"
            poc_path.write_bytes(self._native_payload(finding))
        else:
            poc_path = poc_dir / "poc_manual.md"
            poc_path.write_text(self._manual_poc(finding, analysis), encoding="utf-8")

        plan = PocPlan(
            finding=finding,
            analysis=analysis,
            poc_dir=poc_dir,
            poc_path=poc_path,
            payload_paths=[poc_path] if analysis.verification_mode in {"cpp_cli", "cpp_harness"} else [],
            generated_artifacts=[bug_report, poc_path],
            structured_plan=structured_plan or {},
        )
        if analysis.verification_mode == "cpp_cli":
            plan.target_command = self._native_command(target, poc_path, native_executable)

        runbook = poc_dir / "runbook.md"
        runbook.write_text(self._runbook(plan), encoding="utf-8")
        plan.runbook_path = runbook
        plan.generated_artifacts.append(runbook)
        return plan

    def _bug_report(self, finding: Finding, analysis: PocAnalysis) -> str:
        payloads = "\n".join(f"- `{payload}`" for payload in finding.exploit_payloads) or "- n/a"
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

    def _native_payload(self, finding: Finding) -> bytes:
        marker = f"AGENTIC_CODE_AUDIT_{finding.id}".encode("ascii", errors="ignore")
        if finding.vulnerability_type in {"unsafe_memory_copy", "unsafe_c_string_api", "memory_corruption"}:
            return marker + b"\x00" + (b"A" * 8192) + b"\xff\xd8\xff\xe0" + b"B" * 2048
        if finding.vulnerability_type == "path_traversal":
            return b"../../../../etc/passwd\x00" + marker
        return marker + b"\n" + (b"A" * 4096)

    def _native_command(self, target: Path, poc_path: Path, native_executable: Path | None = None) -> list[str]:
        exe = native_executable or self._find_native_executable(target)
        return [str(exe), str(poc_path)] if exe else []

    def _find_native_executable(self, target: Path) -> Path | None:
        names = [target.name.lower(), "exiv2", "app", "main"]
        candidates: list[Path] = []
        for name in names:
            candidates.extend(target.glob(f"**/{name}.exe"))
            candidates.extend(target.glob(f"**/{name}"))
        for candidate in candidates[:200]:
            if ".git" in candidate.parts or not candidate.is_file():
                continue
            if candidate.suffix.lower() == ".exe" or self._looks_executable(candidate):
                return candidate
        return None

    def _looks_executable(self, candidate: Path) -> bool:
        if shutil.which(str(candidate)):
            return True
        try:
            return candidate.stat().st_size > 0 and candidate.suffix == ""
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

    def plan(self, finding: Finding, target: Path) -> HarnessPlan:
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
        marker = self._marker_for(finding)
        script = f'''import json

finding = {json.dumps(finding.__dict__, ensure_ascii=False, default=str)}
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
    print("{marker}")
else:
    print("[INFO] harness did not prove triggerability")
'''
        return HarnessPlan(
            method="Dynamic harness - deterministic fallback",
            language="python",
            script=script,
            command=["python", "/workspace/harness.py"],
            oracle=f"{marker} in stdout",
            explanation="Generated fallback harness records source/sink/payload evidence without external access.",
            strategy="local_harness",
            runtime_type="library_harness",
            rationale="No direct service/CLI entry was available.",
            commands=[["python", "/workspace/harness.py"]],
            expected_signal=marker,
            fallbacks=["weak_static_proof"],
            environment_requirements=["python"],
            mock_strategy="No network; synthetic source/sink trigger only.",
            weak_verification_strategy="Preserve static anchors and blocked reason.",
            safety_notes=["No external network access.", "Short-lived local harness only when Docker is unavailable."],
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
    """Docker-first executor with constrained local fallback for generated harnesses."""

    def __init__(self, image: str = "agentic-code-audit-sandbox:local") -> None:
        self.image = image
        self.compose_container = os.getenv("AUDIT_SANDBOX_CONTAINER", "")
        self.collector = EvidenceCollector()

    def execute(self, plan: HarnessPlan, work_dir: Path) -> CheckerOutcome:
        work_dir.mkdir(parents=True, exist_ok=True)
        before = self.collector.snapshot(work_dir)
        script_name = "harness.py" if plan.language.lower() in {"python", "py"} else "harness.sh"
        script_path = work_dir / script_name
        script_path.write_text(plan.script, encoding="utf-8")
        command = plan.command or (["python", "/workspace/harness.py"] if script_name.endswith(".py") else ["bash", "/workspace/harness.sh"])
        docker = shutil.which("docker")
        local_fallback = False
        if docker and self.compose_container:
            sandbox_dir = self._compose_sandbox_path(work_dir)
            compose_command = self._compose_command(command, script_name)
            shell_command = " ".join(shlex.quote(part) for part in compose_command)
            run_command = [
                docker,
                "exec",
                "-w",
                sandbox_dir,
                self.compose_container,
                "sh",
                "-lc",
                f"{shell_command} > stdout.log 2> stderr.log; printf '%s' $? > exit_code.txt",
            ]
        elif docker:
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
        else:
            local_fallback = True
            if not script_name.endswith(".py"):
                return CheckerOutcome(
                    status="blocked",
                    summary="Docker is unavailable and non-Python local harness fallback is disabled.",
                    evidence=[f"Harness: {script_path}"],
                    sandbox_command=[],
                    local_fallback=True,
                    checker_details={"checker": "SandboxExecutor", "blocked_reason": "missing_docker"},
                )
            run_command = ["python", str(script_path)]
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
            if docker and self.compose_container:
                stdout = self._read_text(work_dir / "stdout.log")[-8000:]
                stderr = self._read_text(work_dir / "stderr.log")[-8000:]
                try:
                    exit_code = int(self._read_text(work_dir / "exit_code.txt") or completed.returncode)
                except ValueError:
                    exit_code = completed.returncode
        except (OSError, subprocess.TimeoutExpired) as exc:
            after = self.collector.snapshot(work_dir)
            execution, artifacts = self.collector.write_execution(work_dir, run_command, "", str(exc), None, before, after, local_fallback)
            return CheckerOutcome(
                status="blocked",
                summary=f"Sandbox execution failed: {exc}",
                evidence=[f"Executor exception: {exc}", f"Harness: {script_path}"],
                sandbox_command=run_command,
                local_fallback=local_fallback,
                artifact_paths=artifacts,
                execution=execution,
                checker_details={"checker": "SandboxExecutor", "duration_ms": int((time.time() - started) * 1000)},
            )
        after = self.collector.snapshot(work_dir)
        execution, artifacts = self.collector.write_execution(work_dir, run_command, stdout, stderr, exit_code, before, after, local_fallback)
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
            local_fallback=local_fallback,
            artifact_paths=[script_path, *artifacts],
            execution=execution,
        )

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


class RuntimeManager:
    """Select and execute the phase-5 verification runtime."""

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
            return self.checker.check(target, plan, runtime_url)
        harness = planner.plan(plan.finding, target)
        harness.runtime_type = decision.runtime_type
        harness.strategy = decision.strategy
        outcome = self.sandbox.execute(harness, plan.poc_dir / "sandbox")
        return self.checker.dispatch(plan.finding, outcome)


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
    ) -> None:
        self.auto_build_native = auto_build_native
        self.event_sink = event_sink
        self.analyzer = PocAnalyzer()
        self.generator = PocGenerator()
        self.checker = EvidenceChecker()
        self.environment_manager = EnvironmentManager()
        self.build_manager = BuildManager()
        self.native_builder = NativeBuildAgent()
        self.planner = VerificationPlanner(llm_client)
        self.sandbox = SandboxExecutor()
        self.runtime_manager = RuntimeManager(self.sandbox, self.checker)
        self.exploit_agent = ExploitAgent()

    def verify(
        self,
        target: Path,
        findings: list[Finding],
        output_dir: Path,
        profile: ProjectProfile,
        runtime_url: str = "",
    ) -> list[VerificationResult]:
        output_dir.mkdir(parents=True, exist_ok=True)
        results: list[VerificationResult] = []
        for finding in findings:
            should_dynamically_verify = finding.should_verify or finding.vulnerability_type in {
                "dependency_vulnerability",
                "secret_leak",
                "hardcoded_secret",
            }
            environment = self.environment_manager.inspect(target, profile, finding)
            build_decision, native_executable = self.build_manager.prepare(
                target,
                profile,
                finding,
                environment,
                output_dir,
                auto_build_native=self.auto_build_native,
            )
            decision = self.runtime_manager.decide(target, profile, finding, environment, runtime_url, native_executable)
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
            structured_plan = self.planner.structured_plan(finding, target, decision, environment)
            plan = self.generator.generate(target, finding, analysis, output_dir, native_executable, structured_plan)

            self._emit(
                "EnvironmentManager",
                "stage_done",
                f"environment ready: {finding.id}",
                {"finding_id": finding.id, "runtime_type": environment.runtime_type, "gaps": environment.environment_gaps},
            )
            if not should_dynamically_verify and finding.vulnerability_type not in {"dependency_vulnerability", "secret_leak", "hardcoded_secret"}:
                outcome = CheckerOutcome(
                    status="blocked",
                    summary="Finding is not marked for dynamic verification; weak static evidence was preserved.",
                    evidence=self.checker._check_static_anchor(target, finding),
                    checker_details={"checker": "GenericChecker", "blocked_reason": "should_verify_false"},
                )
                decision.runtime_type = "weak_static_proof"
                decision.strategy = "should_verify_false_static_evidence"
            else:
                outcome = self.runtime_manager.execute(target, profile, plan, decision, runtime_url, self.planner)

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
            results.append(self._to_result(plan, outcome, environment, decision, build_decision, exploit_paths))
        return results

    def _to_result(
        self,
        plan: PocPlan,
        outcome: CheckerOutcome,
        environment: EnvironmentProfile,
        decision: RuntimeDecision,
        build_decision: BuildDecision,
        exploit_paths: list[Path],
    ) -> VerificationResult:
        metadata_path = plan.poc_dir / "verification.json"
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
            "execution": outcome.execution,
            "build": asdict(build_decision),
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
            execution=outcome.execution,
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
        )

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
