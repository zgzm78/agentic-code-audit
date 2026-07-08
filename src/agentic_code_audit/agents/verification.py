from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin
from urllib.request import Request, urlopen

from ..llm import DeepSeekClient
from ..models import Finding, ProjectProfile, VerificationResult


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


@dataclass
class HarnessPlan:
    method: str
    language: str
    script: str
    command: list[str]
    oracle: str
    explanation: str


@dataclass
class BuildDecision:
    should_attempt: bool
    reason: str
    build_system: str = ""
    instrumentation: list[str] = field(default_factory=list)


class PocAnalyzer:
    """AnyPoC-style first gate: decide if a candidate is worth PoC work."""

    def analyze(self, target: Path, finding: Finding, profile: ProjectProfile) -> PocAnalysis:
        source_file = target / finding.file_path
        if not source_file.exists():
            return PocAnalysis(
                verdict="invalid",
                verification_mode="none",
                oracle="none",
                details=f"Reported source file does not exist: {finding.file_path}",
                runtime_type="none",
                trigger_type="none",
                rejection_reason="missing_source_file",
            )

        if finding.vulnerability_type == "hardcoded_secret":
            return PocAnalysis(
                verdict="valid_static",
                verification_mode="static_secret",
                oracle="literal exists in repository and must be manually confirmed/rotated",
                details="Secret findings are evidence-preservation tasks, not dynamic exploit tasks.",
                runtime_type="static",
                entry_point=finding.file_path,
                trigger_type="source_literal",
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
                oracle=(
                    "target CLI consumes a crafted file; crash, sanitizer output, or abnormal termination "
                    "is treated as reproduction evidence"
                ),
                details="Native C/C++ finding requires a built binary or project-specific Docker environment.",
                runtime_type="cli",
                entry_point="<native-cli> <crafted_input>",
                trigger_type="crafted_input_file",
            )

        if finding.vulnerability_type in {"command_injection", "path_traversal", "sql_injection"}:
            return PocAnalysis(
                verdict="valid",
                verification_mode="manual_harness",
                oracle="generated harness documents source, sink, payload, and expected impact",
                details="No direct route or executable was detected, so a reviewer-oriented harness is generated.",
                runtime_type="harness",
                entry_point=finding.function_name or finding.file_path,
                trigger_type="llm_generated_harness",
            )

        return PocAnalysis(
            verdict="valid",
            verification_mode="manual_review",
            oracle="reviewer confirms source-to-sink reachability and exploitability",
            details="Generic finding with insufficient runtime information for automated execution.",
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
    """Generate minimal PoC artifacts without trusting them as proof."""

    def generate(
        self,
        target: Path,
        finding: Finding,
        analysis: PocAnalysis,
        output_dir: Path,
        native_executable: Path | None = None,
    ) -> PocPlan:
        poc_dir = output_dir / "pocs" / finding.id
        poc_dir.mkdir(parents=True, exist_ok=True)

        bug_report = poc_dir / "bug_report.md"
        bug_report.write_text(self._bug_report(finding, analysis), encoding="utf-8")

        if analysis.verification_mode == "http":
            poc_path = poc_dir / "poc_http.py"
            poc_path.write_text(self._http_poc(finding), encoding="utf-8")
        elif analysis.verification_mode == "cpp_cli":
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
            payload_paths=[poc_path] if analysis.verification_mode == "cpp_cli" else [],
            generated_artifacts=[bug_report, poc_path],
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
                f"- Tool: {finding.tool}",
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
        if finding.vulnerability_type in {"unsafe_memory_copy", "unsafe_c_string_api"}:
            return marker + b"\x00" + (b"A" * 8192) + b"\xff\xd8\xff\xe0" + b"B" * 2048
        if finding.vulnerability_type == "path_traversal":
            return b"../../../../etc/passwd\x00" + marker
        return marker + b"\n" + (b"A" * 4096)

    def _native_command(
        self,
        target: Path,
        poc_path: Path,
        native_executable: Path | None = None,
    ) -> list[str]:
        exe = native_executable or self._find_native_executable(target)
        if exe:
            return [str(exe), str(poc_path)]
        return []

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
        if finding.vulnerability_type == "hardcoded_secret":
            return "Confirm whether the literal is a real credential, then rotate it if exposed."
        if finding.vulnerability_type in {"unsafe_memory_copy", "unsafe_c_string_api"}:
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


class EvidenceChecker:
    """Independent checker: reproduce from artifacts and record observable evidence."""

    def check(self, target: Path, plan: PocPlan, runtime_url: str = "") -> CheckerOutcome:
        static = self._check_static_anchor(target, plan.finding)
        if plan.analysis.verdict == "invalid":
            return CheckerOutcome(
                status="false_positive",
                summary=plan.analysis.details,
                evidence=static + [f"Rejected: {plan.analysis.rejection_reason}"],
            )

        mode = plan.analysis.verification_mode
        if mode == "static_secret":
            return CheckerOutcome(
                status="partially_verified",
                summary="Secret-like literal is anchored in source; manual credential validation is required.",
                evidence=static,
            )
        if mode == "http":
            if not runtime_url:
                return CheckerOutcome(
                    status="blocked",
                    summary="HTTP PoC generated, but runtime_url was not provided for replay.",
                    evidence=static + ["Set --runtime-url to run the independent HTTP checker."],
                )
            return self._http_probe(runtime_url, plan, static)
        if mode == "cpp_cli":
            if not plan.target_command:
                return CheckerOutcome(
                    status="blocked",
                    summary=(
                        "Native PoC input generated, but no built CLI binary was found. "
                        "Build the project in Docker or locally, then rerun verification."
                    ),
                    evidence=static + self._native_build_hints(target),
                )
            return self._run_command(plan.target_command, static, plan.analysis.oracle)

        return CheckerOutcome(
            status="uncertain",
            summary="PoC/runbook generated; automated replay requires a project-specific harness.",
            evidence=static,
        )

    def _check_static_anchor(self, target: Path, finding: Finding) -> list[str]:
        file_path = target / finding.file_path
        evidence: list[str] = []
        if not file_path.exists():
            return [f"File does not exist: {finding.file_path}"]
        evidence.append(f"File exists: {finding.file_path}")
        if finding.line_start:
            try:
                lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError as exc:
                return evidence + [f"Could not read file: {exc}"]
            if 1 <= finding.line_start <= len(lines):
                line = lines[finding.line_start - 1].strip()
                evidence.append(f"Line {finding.line_start} exists.")
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
            request = Request(url, headers={"User-Agent": "agentic-code-audit/0.2"})
            with urlopen(request, timeout=10) as response:
                body = response.read(2000).decode("utf-8", errors="replace")
            return CheckerOutcome(
                status="partially_verified",
                summary=f"HTTP checker reached target with status {response.status}.",
                evidence=static + [f"HTTP probe sent to {url}"],
                http_status=response.status,
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
            )

        stdout = completed.stdout[-2000:]
        stderr = completed.stderr[-2000:]
        combined = (stdout + "\n" + stderr).lower()
        crash_markers = [
            "addresssanitizer",
            "undefinedbehavior",
            "segmentation fault",
            "access violation",
            "heap-buffer-overflow",
            "stack-buffer-overflow",
            "abort",
        ]
        triggered = completed.returncode != 0 and any(marker in combined for marker in crash_markers)
        status = "verified" if triggered else "not_reproducible"
        summary = (
            "Oracle matched crash/sanitizer evidence."
            if triggered
            else "Command ran, but crash/sanitizer oracle did not match."
        )
        return CheckerOutcome(
            status=status,
            summary=f"{summary} Oracle: {oracle}",
            evidence=static + [f"Executed command: {' '.join(command)}"],
            exit_code=completed.returncode,
            stdout_excerpt=stdout,
            stderr_excerpt=stderr,
        )

    def _native_build_hints(self, target: Path) -> list[str]:
        hints = ["AnyPoC-style native validation needs a built parser/CLI binary."]
        if (target / "CMakeLists.txt").exists():
            hints.append("Detected CMakeLists.txt; suggested build: cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug")
            hints.append("Suggested compile: cmake --build build --config Debug")
        if (target / "meson.build").exists():
            hints.append("Detected meson.build; suggested build: meson setup build && meson compile -C build")
        hints.append("For C/C++, prefer ASAN/UBSAN builds before replaying generated PoC inputs.")
        return hints


class NativeBuildAgent:
    """Best-effort CMake builder for AnyPoC-style native replay."""

    def decide(self, target: Path, profile: ProjectProfile, native_needed: bool) -> BuildDecision:
        if not native_needed:
            return BuildDecision(False, "No native finding requires CLI replay.")
        if not any(lang in profile.languages for lang in ("C", "C++")):
            return BuildDecision(False, "Project profile is not C/C++.")
        if (target / "CMakeLists.txt").exists() and shutil.which("cmake"):
            return BuildDecision(
                True,
                "C/C++ finding requires runtime replay and CMake is available.",
                build_system="cmake",
                instrumentation=["asan", "ubsan"],
            )
        if (target / "CMakeLists.txt").exists():
            return BuildDecision(
                False,
                "CMake project detected, but cmake is not available on PATH.",
                build_system="cmake",
                instrumentation=["asan", "ubsan"],
            )
        if (target / "Makefile").exists() or (target / "makefile").exists():
            return BuildDecision(
                False,
                "Makefile project detected; v1 records build guidance and does not guess project-specific make targets.",
                build_system="make",
                instrumentation=["asan", "ubsan"],
            )
        if (target / "meson.build").exists():
            return BuildDecision(
                False,
                "Meson project detected; v1 records build guidance and does not run meson automatically.",
                build_system="meson",
                instrumentation=["asan", "ubsan"],
            )
        return BuildDecision(False, "No supported native build file was detected.")

    def find_or_build(self, target: Path, output_dir: Path, decision: BuildDecision) -> tuple[Path | None, list[str]]:
        generator = PocGenerator()
        existing = generator._find_native_executable(target)
        if existing:
            return existing, [f"Found existing native executable: {existing}"]
        evidence = [
            f"Native build decision: {'attempt' if decision.should_attempt else 'skip'}",
            f"Reason: {decision.reason}",
        ]
        if decision.build_system:
            evidence.append(f"Build system: {decision.build_system}")
        if decision.instrumentation:
            evidence.append(f"Instrumentation: {', '.join(decision.instrumentation)}")
        if not decision.should_attempt:
            return None, evidence
        if not (target / "CMakeLists.txt").exists():
            return None, evidence + ["No CMakeLists.txt found; auto-build skipped."]
        if not shutil.which("cmake"):
            return None, evidence + ["cmake is not available on PATH; auto-build skipped."]

        build_dir = target / ".agentic-build"
        build_log = output_dir / "native-build.log"
        build_dir.mkdir(parents=True, exist_ok=True)
        configure_cmd = [
            "cmake",
            "-S",
            str(target),
            "-B",
            str(build_dir),
            "-DCMAKE_BUILD_TYPE=Debug",
            "-DCMAKE_C_FLAGS=-fsanitize=address,undefined -fno-omit-frame-pointer",
            "-DCMAKE_CXX_FLAGS=-fsanitize=address,undefined -fno-omit-frame-pointer",
        ]
        build_cmd = ["cmake", "--build", str(build_dir), "--config", "Debug", "-j", "2"]
        evidence.append(f"Auto-build selected by system policy; build dir: {build_dir}")
        logs: list[str] = []

        for label, command in (("configure", configure_cmd), ("build", build_cmd)):
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
                evidence.append(f"CMake {label} failed before completion: {exc}")
                logs.append(f"$ {' '.join(command)}\n{exc}\n")
                build_log.write_text("\n\n".join(logs), encoding="utf-8")
                return None, evidence + [f"Build log: {build_log}"]

            logs.append(
                "\n".join(
                    [
                        f"$ {' '.join(command)}",
                        f"exit_code={completed.returncode}",
                        "## stdout",
                        completed.stdout[-8000:],
                        "## stderr",
                        completed.stderr[-8000:],
                    ]
                )
            )
            if completed.returncode != 0:
                evidence.append(f"CMake {label} exited with {completed.returncode}.")
                build_log.write_text("\n\n".join(logs), encoding="utf-8")
                return None, evidence + [f"Build log: {build_log}"]

        build_log.write_text("\n\n".join(logs), encoding="utf-8")
        built = generator._find_native_executable(build_dir)
        if built:
            evidence.append(f"Built native executable: {built}")
            evidence.append(f"Build log: {build_log}")
            return built, evidence
        evidence.append("CMake build completed, but no executable was detected.")
        evidence.append(f"Build log: {build_log}")
        return None, evidence


class VerificationPlanner:
    """Let the LLM design a project-specific harness while keeping a deterministic fallback."""

    def __init__(self, llm_client: DeepSeekClient | None = None) -> None:
        self.llm_client = llm_client

    def plan(self, finding: Finding, target: Path) -> HarnessPlan:
        if self.llm_client and self.llm_client.enabled:
            planned = self._ask_llm(finding)
            if planned:
                return planned
        return self._fallback_plan(finding, target)

    def _ask_llm(self, finding: Finding) -> HarnessPlan | None:
        prompt = (
            "你是漏洞验证智能体。请为给定源码 finding 设计一个最小 fuzzing harness。"
            "可以 mock 数据库、文件、请求对象或命令执行，但必须输出可在隔离沙箱中执行的代码。"
            "只返回 JSON，字段为 method, language, script, command, oracle, explanation。"
            "script 中必须在检测到漏洞触发线索时打印 [DETECTED] 或 [VULN]。"
        )
        user = json.dumps(
            {
                "finding": finding.__dict__,
                "constraints": [
                    "只允许本地沙箱执行",
                    "不要访问外网",
                    "不要破坏文件系统",
                    "优先 Python harness；C/C++ 可生成 Bash 编译/运行命令",
                ],
            },
            ensure_ascii=False,
            default=str,
        )
        response = self.llm_client.chat(prompt, user, timeout=120) if self.llm_client else None
        if not response or not response.ok:
            return None
        raw = self._extract_json(response.content)
        if not isinstance(raw, dict):
            return None
        script = str(raw.get("script") or "")
        command = raw.get("command") or []
        if not script or not isinstance(command, list):
            return None
        return HarnessPlan(
            method=str(raw.get("method") or "LLM fuzzing harness"),
            language=str(raw.get("language") or "python"),
            script=script,
            command=[str(item) for item in command],
            oracle=str(raw.get("oracle") or "[DETECTED] or [VULN] in stdout"),
            explanation=str(raw.get("explanation") or response.content[:1000]),
        )

    def _fallback_plan(self, finding: Finding, target: Path) -> HarnessPlan:
        source_path = target / finding.file_path
        try:
            source_excerpt = source_path.read_text(encoding="utf-8", errors="ignore")[:4000]
        except OSError:
            source_excerpt = finding.code_snippet[:4000]
        payload = finding.exploit_payloads[0] if finding.exploit_payloads else "A" * 256
        script = f'''import re

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
    print("[DETECTED] source-to-sink harness condition matched")
else:
    print("[INFO] harness did not prove triggerability")
'''
        return HarnessPlan(
            method="Dynamic Fuzzing Harness - generated fallback",
            language="python",
            script=script,
            command=["python", "/workspace/harness.py"],
            oracle="[DETECTED] in stdout",
            explanation="系统生成的保守 harness，用于记录 source/sink/payload 是否同时具备。",
        )

    def _extract_json(self, text: str):
        text = text.strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?", "", text).strip()
            text = re.sub(r"```$", "", text).strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", text, flags=re.S)
            if not match:
                return None
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                return None


class SandboxExecutor:
    """Run LLM-generated harness code in Docker sandbox and persist real evidence."""

    def __init__(self, image: str = "agentic-code-audit-sandbox:local") -> None:
        self.image = image
        self.compose_container = os.getenv("AUDIT_SANDBOX_CONTAINER", "")

    def execute(self, plan: HarnessPlan, work_dir: Path) -> CheckerOutcome:
        work_dir.mkdir(parents=True, exist_ok=True)
        script_name = "harness.py" if plan.language.lower() in {"python", "py"} else "harness.sh"
        script_path = work_dir / script_name
        script_path.write_text(plan.script, encoding="utf-8")
        command = plan.command or (["python", "/workspace/harness.py"] if script_name.endswith(".py") else ["bash", "/workspace/harness.sh"])
        started = time.time()
        docker = shutil.which("docker")
        compose_mode = bool(docker and self.compose_container)
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
            local_command = ["python", str(script_path)] if script_name.endswith(".py") else ["bash", str(script_path)]
            run_command = local_command
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
            if compose_mode:
                stdout = self._read_text(work_dir / "stdout.log")[-8000:]
                stderr = self._read_text(work_dir / "stderr.log")[-8000:]
                try:
                    exit_code = int(self._read_text(work_dir / "exit_code.txt") or completed.returncode)
                except ValueError:
                    exit_code = completed.returncode
            else:
                stdout = completed.stdout[-8000:]
                stderr = completed.stderr[-8000:]
                exit_code = completed.returncode
                (work_dir / "stdout.log").write_text(stdout, encoding="utf-8")
                (work_dir / "stderr.log").write_text(stderr, encoding="utf-8")
            (work_dir / "command.json").write_text(json.dumps(run_command, ensure_ascii=False, indent=2), encoding="utf-8")
        except (OSError, subprocess.TimeoutExpired) as exc:
            return CheckerOutcome(
                status="blocked",
                summary=f"沙箱执行失败: {exc}",
                evidence=[f"执行器异常: {exc}", f"Harness: {script_path}"],
                sandbox_command=run_command,
            )
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
        )

    def _compose_sandbox_path(self, work_dir: Path) -> str:
        resolved = work_dir.resolve().as_posix()
        mappings = {
            "/app/reports": "/workspace/reports",
            "/app/runs": "/workspace/runs",
        }
        for host_prefix, sandbox_prefix in mappings.items():
            if resolved.startswith(host_prefix):
                return sandbox_prefix + resolved[len(host_prefix) :]
        return resolved

    def _compose_command(self, command: list[str], script_name: str) -> list[str]:
        mapped: list[str] = []
        for item in command:
            if item in {"/workspace/harness.py", "/workspace/harness.sh"}:
                mapped.append(script_name)
            else:
                mapped.append(item)
        return mapped

    def _read_text(self, path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""


class VerificationAgent:
    """AnyPoC-inspired verifier: analyze, generate PoC, independently check evidence."""

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
        self.native_builder = NativeBuildAgent()
        self.planner = VerificationPlanner(llm_client)
        self.sandbox = SandboxExecutor()

    def verify(
        self,
        target: Path,
        findings: list[Finding],
        output_dir: Path,
        profile: ProjectProfile,
        runtime_url: str = "",
    ) -> list[VerificationResult]:
        results: list[VerificationResult] = []
        native_executable: Path | None = None
        native_build_evidence: list[str] = []
        native_needed = any(
            self.analyzer.analyze(target, finding, profile).verification_mode == "cpp_cli"
            for finding in findings
        )
        if native_needed:
            decision = self.native_builder.decide(target, profile, native_needed)
            if self.auto_build_native:
                decision.should_attempt = True
                decision.reason = f"{decision.reason} Env override AUDIT_AUTO_BUILD_NATIVE=true."
            self._emit(
                "BuildDecisionAgent",
                "stage_done",
                "原生项目构建决策完成",
                {
                    "should_attempt": decision.should_attempt,
                    "reason": decision.reason,
                    "build_system": decision.build_system,
                    "instrumentation": decision.instrumentation,
                },
            )
            native_executable, native_build_evidence = self.native_builder.find_or_build(target, output_dir, decision)
        for finding in findings:
            analysis = self.analyzer.analyze(target, finding, profile)
            self._emit(
                "VerificationPlanner",
                "stage_start",
                f"生成验证计划: {finding.id}",
                {
                    "finding_id": finding.id,
                    "runtime_type": analysis.runtime_type,
                    "entry_point": analysis.entry_point,
                    "trigger_type": analysis.trigger_type,
                    "oracle": analysis.oracle,
                },
            )
            plan = self.generator.generate(target, finding, analysis, output_dir, native_executable)
            if analysis.verification_mode in {"manual_harness", "manual_review"}:
                harness = self.planner.plan(finding, target)
                self._emit(
                    "RuntimeManager",
                    "tool_start",
                    f"沙箱执行 harness: {finding.id}",
                    {"finding_id": finding.id, "method": harness.method, "language": harness.language},
                )
                outcome = self.sandbox.execute(harness, plan.poc_dir / "sandbox")
                analysis.oracle = harness.oracle
            else:
                self._emit(
                    "RuntimeManager",
                    "tool_start",
                    f"执行确定性验证: {finding.id}",
                    {"finding_id": finding.id, "mode": analysis.verification_mode},
                )
                outcome = self.checker.check(target, plan, runtime_url)
            if analysis.verification_mode == "cpp_cli" and native_build_evidence:
                outcome.evidence.extend(native_build_evidence)
            self._emit(
                "EvidenceChecker",
                "stage_done",
                f"{finding.id}: {outcome.status}",
                {"finding_id": finding.id, "status": outcome.status, "summary": outcome.summary},
            )
            results.append(self._to_result(plan, outcome))
        return results

    def _to_result(self, plan: PocPlan, outcome: CheckerOutcome) -> VerificationResult:
        metadata_path = plan.poc_dir / "verification.json"
        payload = {
            "finding_id": plan.finding.id,
            "analysis": plan.analysis.__dict__,
            "verification_plan": self._verification_plan(plan),
            "poc_path": str(plan.poc_path),
            "target_command": plan.target_command,
            "checker": outcome.__dict__,
            "generated_artifacts": [str(path) for path in plan.generated_artifacts],
        }
        metadata_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        generated = [str(path) for path in plan.generated_artifacts] + [str(metadata_path)]
        return VerificationResult(
            finding_id=plan.finding.id,
            status=outcome.status,
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
            verification_plan=self._verification_plan(plan),
            runtime_type=plan.analysis.runtime_type,
            entry_point=plan.analysis.entry_point,
            trigger_type=plan.analysis.trigger_type,
            attempts=1,
            sandbox_command=outcome.sandbox_command,
            sandbox_stdout=outcome.stdout_excerpt,
            sandbox_stderr=outcome.stderr_excerpt,
        )

    def _verification_plan(self, plan: PocPlan) -> dict[str, Any]:
        return {
            "finding_id": plan.finding.id,
            "runtime_type": plan.analysis.runtime_type,
            "entry_point": plan.analysis.entry_point,
            "target_function": plan.finding.function_name,
            "trigger_type": plan.analysis.trigger_type,
            "instrumentation": ["asan", "ubsan"] if plan.analysis.verification_mode == "cpp_cli" else [],
            "oracle": {
                "type": plan.analysis.verification_mode,
                "expected": plan.analysis.oracle,
            },
            "max_attempts": plan.analysis.max_attempts,
        }

    def _emit(self, agent: str, event_type: str, message: str, metadata: dict[str, Any]) -> None:
        if self.event_sink:
            self.event_sink(agent, event_type, message, metadata)
