from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..audit_budget import AuditBudget, BudgetUsage
from ..llm import DeepSeekClient
from ..normalizer import VulnerabilityTypeNormalizer
from ..vulnerability_types import VulnType, RiskDomain, risk_domain_for, is_dynamic_verification_candidate
from .mining_director import MiningStrategy
from ..models import (
    AgentEvent,
    ChainEdge,
    ChainGraph,
    ChainNode,
    DangerousFunction,
    Finding,
    ProgramSlice,
    ProjectProfile,
    SemanticIndex,
    ToolResult,
    VulnerabilityCandidate,
    normalize_path,
    utc_now,
)
from ..rules import RulesLoader
from ..tools.runner import SecurityToolRunner, ToolPlanner, ToolRunner, run_invocations_parallel


WEAK_CPP_APIS = {
    "array_index",
    "array_index_offset",
    "c_style_cast",
    "open",
    "mmap",
    "fopen",
    "new[]",
    "malloc",
    "calloc",
    "realloc",
    "free",
    "delete",
    "delete[]",
    "memcmp",
    "std::copy",
    "copy",
}


def coerce_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (int, float, bool)):
        return [str(value)]
    if isinstance(value, dict):
        return [json.dumps(value, ensure_ascii=False)]
    if isinstance(value, (list, tuple, set)):
        output: list[str] = []
        for item in value:
            output.extend(coerce_str_list(item))
        return output
    return [str(value)]


@dataclass
class MiningResult:
    tool_results: list[ToolResult] = field(default_factory=list)
    dangerous_functions: list[DangerousFunction] = field(default_factory=list)
    program_slices: list[ProgramSlice] = field(default_factory=list)
    candidates: list[VulnerabilityCandidate] = field(default_factory=list)
    aggregated_candidates: list[VulnerabilityCandidate] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    events: list[AgentEvent] = field(default_factory=list)
    strategy: dict[str, Any] | None = None
    budget: dict[str, Any] = field(default_factory=dict)
    budget_usage: dict[str, Any] = field(default_factory=dict)
    strategy_effects: dict[str, Any] = field(default_factory=dict)


class DangerousFunctionLocator:
    """Locate dangerous APIs by merging rules, tool anchors, and boundary extraction hints."""

    COMMON_PATTERNS = [
        (r"execute\s*\(.*(%|\+|format|f[\"'])", "execute", "sql_injection", "sql", 0.8),
        (r"SELECT\s+.*\+", "sql_concat", "sql_injection", "sql", 0.65),
        (r"open\s*\(.*request\.", "open", "path_traversal", "file", 0.72),
        (r"send_file\s*\(", "send_file", "path_traversal", "file", 0.55),
    ]

    SUFFIX_LANGUAGE = {
        ".py": "Python",
        ".js": "JavaScript",
        ".jsx": "JavaScript",
        ".ts": "TypeScript",
        ".tsx": "TypeScript",
        ".c": "C",
        ".cc": "C++",
        ".cpp": "C++",
        ".cxx": "C++",
        ".h": "C/C++",
        ".hpp": "C++",
        ".go": "Go",
        ".rs": "Rust",
    }

    def __init__(self, rules_loader: RulesLoader | None = None) -> None:
        self.rules_loader = rules_loader or RulesLoader()
        self.normalizer = VulnerabilityTypeNormalizer()
        self.last_suppressed_counts: dict[str, int] = {}

    def locate(
        self,
        target: Path,
        tool_results: list[ToolResult],
        budget: AuditBudget | None = None,
        strategy: MiningStrategy | None = None,
    ) -> list[DangerousFunction]:
        rules = self.rules_loader.load()
        boundary_hints = self._boundary_hints(target)
        skipped_optional = [item.tool for item in tool_results if item.status == "skipped"]
        anchors = self._from_rules(target, rules, boundary_hints, skipped_optional)
        anchors.extend(self._from_tools(target, tool_results, boundary_hints))
        merged = self._merge([self._enrich_anchor(anchor) for anchor in anchors])
        filtered = self._filter_and_rank(merged, budget, strategy)
        return filtered[: budget.max_anchors] if budget else filtered

    def _from_rules(
        self,
        target: Path,
        rules: dict[str, Any],
        boundary_hints: dict[str, list[dict[str, Any]]],
        skipped_optional: list[str],
    ) -> list[DangerousFunction]:
        anchors: list[DangerousFunction] = []
        # Merge dangerous_functions + sinks for C/C++ rule set
        cpp_func_rules = list(rules.get("cpp.dangerous_functions", {}).get("rules") or [])
        cpp_sink_rules = list(rules.get("cpp.sinks", {}).get("rules") or [])
        cpp_merged = cpp_func_rules + cpp_sink_rules
        grouped_rules = {
            ".py": list(rules.get("python.dangerous_apis", {}).get("rules") or []),
            ".js": list(rules.get("javascript.dangerous_apis", {}).get("rules") or []),
            ".jsx": list(rules.get("javascript.dangerous_apis", {}).get("rules") or []),
            ".ts": list(rules.get("javascript.dangerous_apis", {}).get("rules") or []),
            ".tsx": list(rules.get("javascript.dangerous_apis", {}).get("rules") or []),
            ".c": cpp_merged,
            ".cc": cpp_merged,
            ".cpp": cpp_merged,
            ".cxx": cpp_merged,
            ".h": cpp_merged,
            ".hpp": cpp_merged,
        }
        # Load parser entry patterns for C/C++ projects
        parser_patterns = rules.get("cpp.parser_patterns", {})
        common_rules = [
            {"pattern": pattern, "api": api, "vuln_type": vuln_type, "category": category, "confidence": confidence}
            for pattern, api, vuln_type, category, confidence in self.COMMON_PATTERNS
        ]
        # Directories to skip during anchor collection (test code, build artifacts)
        SKIP_DIRS = {"tests", "test", "__tests__", "__test__", "testing", "fuzz", "build", ".git"}
        for path in target.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in self.SUFFIX_LANGUAGE or ".git" in path.parts:
                continue
            # Skip test/build directories
            if any(d in SKIP_DIRS for d in path.parts):
                continue
            try:
                lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            rel = normalize_path(path, target)
            suffix = path.suffix.lower()
            file_rules = grouped_rules.get(suffix, []) + common_rules
            for index, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith(("#", "//", "*")):
                    continue
                for rule in file_rules:
                    if not re.search(str(rule["pattern"]), line, flags=re.IGNORECASE):
                        continue
                    function_name = self._nearest_function(rel, index, boundary_hints)
                    evidence = [f"rule_match:{rule['api']}"]
                    if skipped_optional:
                        evidence.append(f"optional_tools_not_run:{','.join(sorted(set(skipped_optional)))}")
                    anchors.append(
                        DangerousFunction(
                            id=self._id(rel, index, str(rule["api"])),
                            file_path=rel,
                            line_start=index,
                            function_name=function_name,
                            dangerous_api=str(rule["api"]),
                            category=str(rule["category"]),
                            snippet=stripped[:500],
                            language=self.SUFFIX_LANGUAGE.get(suffix, ""),
                            kind="dangerous_api",
                            rule_id=f"rules.{rule['vuln_type']}.{rule['api']}",
                            confidence=float(rule["confidence"]),
                            sink=str(rule["api"]),
                            evidence=evidence,
                            tool="rules",
                            rule_vuln_type=str(rule.get("vuln_type") or ""),
                            anchor_category=str(rule.get("category") or ""),
                            weak_signal=bool(rule.get("weak_signal")) or str(rule.get("api") or "") in WEAK_CPP_APIS,
                            optional_tools_not_run=sorted(set(skipped_optional)),
                        )
                    )
        return anchors

    def _from_tools(
        self, target: Path, tool_results: list[ToolResult],
        boundary_hints: dict[str, list[dict[str, Any]]] | None = None,
    ) -> list[DangerousFunction]:
        hints = boundary_hints or {}
        anchors: list[DangerousFunction] = []
        for result in tool_results:
            if result.tool == "semgrep" and isinstance(result.raw, dict):
                anchors.extend(self._semgrep_anchors(result))
            elif result.tool == "bandit" and isinstance(result.raw, dict):
                anchors.extend(self._bandit_anchors(result))
            elif result.tool == "cppcheck":
                anchors.extend(self._cppcheck_anchors(target, result, hints))
            elif result.tool == "clang-tidy":
                anchors.extend(self._clang_tidy_anchors(target, result, hints))
            elif result.tool == "gosec" and isinstance(result.raw, dict):
                anchors.extend(self._gosec_anchors(target, result))
            elif result.tool in {"npm-audit", "pip-audit", "cargo-audit", "osv-scanner", "trivy"}:
                anchors.extend(self._dependency_anchors(result))
            elif result.tool == "gitleaks" and isinstance(result.raw, list):
                anchors.extend(self._secret_anchors(result))
        return anchors

    def _semgrep_anchors(self, result: ToolResult) -> list[DangerousFunction]:
        anchors: list[DangerousFunction] = []
        artifact_refs = self._artifact_refs(result)
        for item in result.raw.get("results", []):
            path = str(item.get("path") or "")
            line = int(item.get("start", {}).get("line") or 1)
            check_id = str(item.get("check_id") or "semgrep")
            extra = item.get("extra", {}) or {}
            is_config = self._is_config_security_finding(path, check_id)
            anchors.append(
                DangerousFunction(
                    id=self._id(path, line, check_id),
                    file_path=path,
                    line_start=line,
                    function_name=self._config_component(path, check_id) if is_config else "",
                    dangerous_api=check_id,
                    category="configuration" if is_config else "tool",
                    snippet=str(extra.get("lines") or "").strip()[:500],
                    language="YAML" if is_config else "",
                    kind="configuration_security" if is_config else "tool_finding",
                    rule_id=check_id,
                    confidence=0.66,
                    sink=check_id,
                    evidence=[str(extra.get("message") or "semgrep finding")],
                    tool_run_refs=[result.run_id],
                    artifact_refs=artifact_refs,
                    tool="semgrep",
                )
            )
        return anchors

    def _is_config_security_finding(self, path: str, check_id: str) -> bool:
        value = f"{path} {check_id}".lower().replace("\\", "/")
        config_suffix = Path(path).suffix.lower() in {".yml", ".yaml", ".json", ".toml"}
        config_path = any(token in value for token in (".github/workflows/", "dependabot", "github-actions"))
        config_rule = any(
            token in value
            for token in (
                "github-actions",
                "dependabot",
                "mutable-action",
                "pinned",
                "workflow",
                "supply-chain",
            )
        )
        return config_suffix and (config_path or config_rule)

    def _config_component(self, path: str, check_id: str) -> str:
        value = path.replace("\\", "/").lower()
        if ".github/workflows/" in value:
            return "github-actions-workflow"
        if "dependabot" in value or "dependabot" in check_id.lower():
            return "dependabot-config"
        return Path(path).stem or "configuration"

    def _bandit_anchors(self, result: ToolResult) -> list[DangerousFunction]:
        anchors: list[DangerousFunction] = []
        artifact_refs = self._artifact_refs(result)
        for item in result.raw.get("results", []):
            path = str(item.get("filename") or "")
            line = int(item.get("line_number") or 1)
            test_id = str(item.get("test_id") or "bandit")
            anchors.append(
                DangerousFunction(
                    id=self._id(path, line, test_id),
                    file_path=path,
                    line_start=line,
                    function_name="",
                    dangerous_api=test_id,
                    category="tool",
                    snippet=str(item.get("code") or "").strip()[:500],
                    language="Python",
                    kind="tool_finding",
                    rule_id=test_id,
                    confidence=0.64,
                    sink=test_id,
                    evidence=[str(item.get("issue_text") or "bandit finding")],
                    tool_run_refs=[result.run_id],
                    artifact_refs=artifact_refs,
                    tool="bandit",
                )
            )
        return anchors

    def _cppcheck_anchors(
        self, target: Path, result: ToolResult,
        boundary_hints: dict[str, list[dict[str, Any]]] | None = None,
    ) -> list[DangerousFunction]:
        hints = boundary_hints or {}
        anchors: list[DangerousFunction] = []
        artifact_refs = self._artifact_refs(result)
        for item in result.findings:
            file_path = self._relative_tool_path(target, str(item.get("location_file") or item.get("file") or ""))
            line = self._int(item.get("location_line") or item.get("line"), 1)
            rule_id = str(item.get("id") or "cppcheck")
            severity = str(item.get("severity") or "")
            msg = str(item.get("msg") or "")
            verbose = str(item.get("verbose") or "")
            evidence_lines = [msg]
            if verbose and verbose != msg:
                evidence_lines.append(verbose)
            if severity:
                evidence_lines.insert(0, f"severity={severity}")
            # Boost confidence for high-severity cppcheck findings
            confidence = 0.62
            if severity in {"error", "warning"}:
                confidence = 0.68
            if "nullPointer" in rule_id or "bufferAccess" in rule_id or "arrayIndex" in rule_id:
                confidence = max(confidence, 0.70)
            fn_name = self._nearest_function(file_path, line, hints)
            anchors.append(
                DangerousFunction(
                    id=self._id(file_path, line, rule_id),
                    file_path=file_path,
                    line_start=line,
                    function_name=fn_name,
                    dangerous_api=rule_id,
                    category="tool",
                    snippet=msg[:500],
                    language="C/C++",
                    kind="tool_finding",
                    rule_id=rule_id,
                    confidence=confidence,
                    sink=rule_id,
                    evidence=evidence_lines,
                    tool_run_refs=[result.run_id],
                    artifact_refs=artifact_refs,
                    tool="cppcheck",
                )
            )
        return anchors

    def _clang_tidy_anchors(
        self, target: Path, result: ToolResult,
        boundary_hints: dict[str, list[dict[str, Any]]] | None = None,
    ) -> list[DangerousFunction]:
        """Extract anchors from clang-tidy findings."""
        hints = boundary_hints or {}
        anchors: list[DangerousFunction] = []
        artifact_refs = self._artifact_refs(result)
        for item in result.findings:
            file_path = self._relative_tool_path(target, str(item.get("file") or ""))
            line = self._int(item.get("line"), 1)
            check_name = str(item.get("check") or "clang-tidy")
            severity = str(item.get("severity") or "warning")
            message = str(item.get("message") or "")
            # Map severity to confidence
            confidence = 0.65
            if severity in {"error", "fatal error"}:
                confidence = 0.75
            elif severity == "warning":
                confidence = 0.68
            elif severity == "note":
                confidence = 0.50
            # Security and bugprone checks get higher default confidence
            if "security" in check_name or "bugprone" in check_name:
                confidence = max(confidence, 0.70)
            evidence = [message]
            if severity:
                evidence.insert(0, f"severity={severity}")
            fn_name = self._nearest_function(file_path, line, hints)
            anchors.append(
                DangerousFunction(
                    id=self._id(file_path, line, check_name),
                    file_path=file_path,
                    line_start=line,
                    function_name=fn_name,
                    dangerous_api=check_name,
                    category="tool",
                    snippet=message[:500],
                    language="C/C++",
                    kind="tool_finding",
                    rule_id=check_name,
                    confidence=confidence,
                    sink=check_name,
                    evidence=evidence,
                    tool_run_refs=[result.run_id],
                    artifact_refs=artifact_refs,
                    tool="clang-tidy",
                )
            )
        return anchors

    def _gosec_anchors(self, target: Path, result: ToolResult) -> list[DangerousFunction]:
        anchors: list[DangerousFunction] = []
        artifact_refs = self._artifact_refs(result)
        for item in result.findings:
            file_path = self._relative_tool_path(target, str(item.get("file") or ""))
            line = self._int(item.get("line"), 1)
            rule_id = str(item.get("rule_id") or item.get("rule") or "gosec")
            anchors.append(
                DangerousFunction(
                    id=self._id(file_path, line, rule_id),
                    file_path=file_path,
                    line_start=line,
                    function_name="",
                    dangerous_api=rule_id,
                    category="tool",
                    snippet=str(item.get("code") or item.get("details") or "")[:500],
                    language="Go",
                    kind="tool_finding",
                    rule_id=rule_id,
                    confidence=0.62,
                    sink=rule_id,
                    evidence=[str(item.get("details") or "gosec finding")],
                    tool_run_refs=[result.run_id],
                    artifact_refs=artifact_refs,
                    tool="gosec",
                )
            )
        return anchors

    def _dependency_anchors(self, result: ToolResult) -> list[DangerousFunction]:
        anchors: list[DangerousFunction] = []
        artifact_refs = self._artifact_refs(result)
        for index, item in enumerate(result.findings[:80], start=1):
            package = item.get("package") or item.get("name") or item.get("module_name") or "dependency"
            vuln_id = (
                item.get("id")
                or item.get("vulnerability_id")
                or item.get("advisory", {}).get("id")
                or item.get("advisory")
                or result.tool
            )
            anchors.append(
                DangerousFunction(
                    id=self._id(str(package), index, str(vuln_id)),
                    file_path=str(package),
                    line_start=1,
                    function_name=str(package),
                    dangerous_api=str(vuln_id),
                    category="dependency",
                    snippet=json.dumps(item, ensure_ascii=False)[:500],
                    kind="dependency_vulnerability",
                    rule_id=str(vuln_id),
                    confidence=0.72,
                    sink=str(package),
                    evidence=[f"{result.tool}:{vuln_id}"],
                    tool_run_refs=[result.run_id],
                    artifact_refs=artifact_refs,
                    tool=result.tool,
                )
            )
        return anchors

    def _secret_anchors(self, result: ToolResult) -> list[DangerousFunction]:
        anchors: list[DangerousFunction] = []
        artifact_refs = self._artifact_refs(result)
        for item in result.raw[:80]:
            path = str(item.get("File") or item.get("file") or "")
            line = self._int(item.get("StartLine") or item.get("line"), 1)
            rule_id = str(item.get("RuleID") or "gitleaks")
            anchors.append(
                DangerousFunction(
                    id=self._id(path, line, rule_id),
                    file_path=path,
                    line_start=line,
                    function_name="",
                    dangerous_api=rule_id,
                    category="secret",
                    snippet=str(item.get("Match") or item.get("Secret") or "")[:500],
                    kind="secret_leak",
                    rule_id=rule_id,
                    confidence=0.84,
                    sink=rule_id,
                    evidence=[f"gitleaks:{rule_id}"],
                    tool_run_refs=[result.run_id],
                    artifact_refs=artifact_refs,
                    tool="gitleaks",
                )
            )
        return anchors

    def _boundary_hints(self, target: Path) -> dict[str, list[dict[str, Any]]]:
        hints: dict[str, list[dict[str, Any]]] = {}
        for path in target.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in self.SUFFIX_LANGUAGE or ".git" in path.parts:
                continue
            rel = normalize_path(path, target)
            hints[rel] = self._extract_boundaries(path)
        return hints

    def _extract_boundaries(self, path: Path) -> list[dict[str, Any]]:
        suffix = path.suffix.lower()
        if suffix == ".py":
            return self._python_boundaries(path)
        if suffix in {".js", ".jsx", ".ts", ".tsx"}:
            return self._js_boundaries(path)
        if suffix in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}:
            return self._cpp_boundaries(path)
        return []

    def _python_boundaries(self, path: Path) -> list[dict[str, Any]]:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, SyntaxError):
            return []
        output: list[dict[str, Any]] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                output.append(
                    {
                        "name": node.name,
                        "start": int(node.lineno),
                        "end": int(getattr(node, "end_lineno", node.lineno)),
                    }
                )
        return output

    def _js_boundaries(self, path: Path) -> list[dict[str, Any]]:
        tree_sitter = self._js_boundaries_with_tree_sitter(path)
        if tree_sitter:
            return tree_sitter
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return []
        output: list[dict[str, Any]] = []
        for index, line in enumerate(lines, start=1):
            match = re.search(r"(?:function|const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)", line)
            if match:
                output.append({"name": match.group(1), "start": index, "end": min(len(lines), index + 20)})
        return output

    def _js_boundaries_with_tree_sitter(self, path: Path) -> list[dict[str, Any]]:
        try:
            import tree_sitter_languages  # type: ignore
        except ImportError:
            return []
        try:
            parser = tree_sitter_languages.get_parser("javascript")
            tree = parser.parse(path.read_bytes())
        except Exception:
            return []
        output: list[dict[str, Any]] = []
        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            if node.type in {"function_declaration", "method_definition"}:
                name_node = node.child_by_field_name("name")
                if name_node is not None:
                    output.append(
                        {
                            "name": path.read_text(encoding="utf-8", errors="ignore")[name_node.start_byte : name_node.end_byte],
                            "start": node.start_point[0] + 1,
                            "end": node.end_point[0] + 1,
                        }
                    )
            stack.extend(node.children)
        return output

    def _cpp_boundaries(self, path: Path) -> list[dict[str, Any]]:
        ctags = shutil.which("ctags")
        if ctags:
            try:
                if ctags == "docker-exec-sandbox-ctags":
                    sandbox_path = str(path).replace("\\", "/")
                    for host_pfx, sbx_pfx in [("/app/", "/workspace/")]:
                        if sandbox_path.startswith(host_pfx):
                            sandbox_path = sbx_pfx + sandbox_path[len(host_pfx):]
                            break
                    proc = subprocess.run(
                        ["docker", "exec", os.getenv("AUDIT_SANDBOX_CONTAINER", "agentic-code-audit-sandbox"), "ctags", "-x", "--c-kinds=f", sandbox_path],
                        text=True, encoding="utf-8", errors="replace",
                        capture_output=True, timeout=10, check=False,
                    )
                else:
                    proc = subprocess.run(
                        [ctags, "-x", "--c-kinds=f", str(path)],
                        text=True, encoding="utf-8", errors="replace",
                        capture_output=True, timeout=10, check=False,
                    )
            except (OSError, subprocess.TimeoutExpired):
                proc = None
            if proc and proc.returncode == 0:
                output: list[dict[str, Any]] = []
                for line in proc.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 3 and parts[2].isdigit():
                        output.append({"name": parts[0], "start": int(parts[2]), "end": int(parts[2]) + 40})
                if output:
                    return output
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return []
        output = []
        for index, line in enumerate(lines, start=1):
            match = re.search(r"(?:[\w:<>\*&]+\s+)+([A-Za-z_~][A-Za-z0-9_:~]*)\s*\([^;{}]*\)\s*(?:\{|$)", line)
            if match:
                output.append({"name": match.group(1).split("::")[-1], "start": index, "end": min(len(lines), index + 50)})
        return output

    def _nearest_function(self, rel_path: str, line_number: int, boundary_hints: dict[str, list[dict[str, Any]]]) -> str:
        for item in boundary_hints.get(rel_path, []):
            if int(item.get("start", 0)) <= line_number <= int(item.get("end", line_number)):
                return str(item.get("name") or "")
        return ""

    def _merge(self, anchors: list[DangerousFunction]) -> list[DangerousFunction]:
        merged: dict[tuple[str, int, str], DangerousFunction] = {}
        for anchor in anchors:
            key = (anchor.file_path, anchor.line_start, anchor.dangerous_api)
            current = merged.get(key)
            if current is None:
                merged[key] = anchor
                continue
            current.confidence = max(current.confidence, anchor.confidence)
            current.tool_run_refs.extend(item for item in anchor.tool_run_refs if item not in current.tool_run_refs)
            current.artifact_refs.extend(item for item in anchor.artifact_refs if item not in current.artifact_refs)
            current.evidence.extend(item for item in anchor.evidence if item not in current.evidence)
            if not current.function_name and anchor.function_name:
                current.function_name = anchor.function_name
            if current.tool == "rules" and anchor.tool != "rules":
                current.tool = anchor.tool
        return sorted(merged.values(), key=lambda item: item.confidence, reverse=True)

    def _enrich_anchor(self, anchor: DangerousFunction) -> DangerousFunction:
        if not anchor.anchor_category:
            anchor.anchor_category = self._anchor_category(anchor)
        if not anchor.rule_vuln_type:
            anchor.rule_vuln_type = self.normalizer.normalize(
                tool=anchor.tool,
                rule_id=anchor.rule_id,
                anchor_category=anchor.anchor_category,
                category=anchor.category,
                sink=anchor.sink or anchor.dangerous_api,
                file_path=anchor.file_path,
            ).value
        if not anchor.risk_domain:
            anchor.risk_domain = risk_domain_for(VulnType.from_string(anchor.rule_vuln_type)).value
        if not anchor.weak_signal:
            anchor.weak_signal = self._is_weak_signal(anchor)
        return anchor

    def _anchor_category(self, anchor: DangerousFunction) -> str:
        path = (anchor.file_path or "").replace("\\", "/").lower()
        if anchor.kind == "configuration_security" or ".github/" in path or "dependabot" in path:
            return "supply_chain_config"
        if anchor.kind == "dependency_vulnerability" or anchor.category == "dependency":
            return "dependency"
        if anchor.kind == "secret_leak" or anchor.category == "secret" or anchor.tool == "gitleaks":
            return "secret"
        if anchor.language in {"C", "C++", "C/C++", "Python", "JavaScript", "TypeScript", "Go", "Rust"}:
            return "source_code"
        return "weak_signal"

    def _is_weak_signal(self, anchor: DangerousFunction) -> bool:
        api = (anchor.dangerous_api or anchor.sink or "").strip()
        if api in WEAK_CPP_APIS:
            return True
        if anchor.category in {"type_safety"}:
            return True
        if anchor.tool == "rules" and anchor.confidence < 0.50:
            return True
        return False

    def _filter_and_rank(
        self,
        anchors: list[DangerousFunction],
        budget: AuditBudget | None,
        strategy: MiningStrategy | None = None,
    ) -> list[DangerousFunction]:
        suppressed = {"config": 0, "weak_signal": 0}
        output: list[DangerousFunction] = []
        for anchor in anchors:
            if strategy and self._is_dismissed_by_strategy(anchor, strategy):
                suppressed["strategy_dismissed"] = suppressed.get("strategy_dismissed", 0) + 1
                continue
            if budget and not budget.enable_config_audit and anchor.anchor_category == "supply_chain_config":
                suppressed["config"] += 1
                continue
            if budget and anchor.weak_signal and anchor.confidence < budget.weak_signal_min_confidence:
                suppressed["weak_signal"] += 1
                continue
            output.append(anchor)
        self.last_suppressed_counts = suppressed

        def rank(anchor: DangerousFunction) -> tuple[int, int, int, float]:
            domain_weight = {
                "source_code": 5,
                "secret": 4,
                "dependency": 3,
                "supply_chain_config": 2,
                "weak_signal": 1,
            }.get(anchor.anchor_category or anchor.risk_domain, 0)
            tool_weight = 2 if anchor.tool and anchor.tool != "rules" else 0
            parser_weight = 1 if self._has_parser_context(anchor) else 0
            strategy_weight = self._strategy_anchor_score(anchor, strategy)
            weak_penalty = -2 if anchor.weak_signal else 0
            return (domain_weight + weak_penalty + strategy_weight, tool_weight, parser_weight, anchor.confidence)

        return sorted(output, key=rank, reverse=True)

    def _is_dismissed_by_strategy(self, anchor: DangerousFunction, strategy: MiningStrategy) -> bool:
        path = (anchor.file_path or "").replace("\\", "/").lower()
        for item in strategy.dismissed_noise:
            dismissed_file = str(item.get("file", "")).replace("\\", "/").lower()
            if dismissed_file and (path == dismissed_file or path.startswith(dismissed_file.rstrip("/") + "/")):
                return True
        return False

    def _strategy_anchor_score(self, anchor: DangerousFunction, strategy: MiningStrategy | None) -> int:
        if not strategy:
            return 0
        score = 0
        path = (anchor.file_path or "").replace("\\", "/")
        function = anchor.function_name or ""
        for directory in strategy.focus_directories:
            prefix = directory.rstrip("/")
            if prefix in {"", "."} or path.startswith(prefix + "/") or path == prefix:
                score += 3
                break
        if function and any(item.lower() in function.lower() for item in strategy.priority_functions):
            score += 8
        if function and any(item.lower() in function.lower() for item in strategy.parser_entries):
            score += 6
        if function and any(item.lower() in function.lower() for item in strategy.dynamic_priority_functions):
            score += 5
        return score

    def _has_parser_context(self, anchor: DangerousFunction) -> bool:
        value = f"{anchor.function_name} {anchor.file_path}".lower()
        return any(token in value for token in ("read", "decode", "parse", "load", "writemetadata", "metadata"))

    def _relative_tool_path(self, target: Path, value: str) -> str:
        if not value:
            return ""
        path = Path(value)
        if path.is_absolute():
            return normalize_path(path, target)
        return value.replace("\\", "/")

    def _artifact_refs(self, result: ToolResult) -> list[str]:
        return [item for item in [result.stdout_artifact_id, result.stderr_artifact_id, result.parsed_artifact_id] if item]

    def _int(self, value: Any, default: int) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _id(self, path: str, line: int, api: str) -> str:
        return hashlib.sha1(f"{path}:{line}:{api}".encode("utf-8")).hexdigest()[:12]


class SliceAnalyzer:
    """Build structured source-to-sink slices with language-aware boundary extraction."""

    STATIC_KINDS = {"dependency_vulnerability", "secret_leak", "configuration_security"}

    def __init__(self, rules_loader: RulesLoader | None = None) -> None:
        self.rules_loader = rules_loader or RulesLoader()
        self._init_patterns()

    def _init_patterns(self) -> None:
        rules = self.rules_loader.load()
        src_rules = rules.get("cpp.sources", {})
        guard_rules = rules.get("cpp.guards", {})
        sanitizer_rules = rules.get("cpp.sanitizers", {})
        parser_rules = rules.get("cpp.parser_patterns", {})
        cpp_sources = list(src_rules.get("patterns") or []) if isinstance(src_rules, dict) else []
        guards_list = list(guard_rules.get("patterns") or []) if isinstance(guard_rules, dict) else []
        sanitizers_list = list(sanitizer_rules.get("patterns") or []) if isinstance(sanitizer_rules, dict) else []
        parser_entries = list(parser_rules.get("entry_patterns") or []) if isinstance(parser_rules, dict) else []
        self.parser_entry_patterns = parser_entries
        # Combine built-in + rule-file patterns
        self.SOURCE_PATTERNS = self._builtin_sources() + cpp_sources
        self.SANITIZER_PATTERNS = self._builtin_sanitizers() + sanitizers_list
        self.GUARD_PATTERNS = guards_list

    @staticmethod
    def _builtin_sources() -> list[str]:
        return [
            r"request\.(args|form|json|values|GET|POST)",
            r"req\.(query|body|params)",
            r"\$_(GET|POST|REQUEST)",
            r"\bargv\b|\bargc\b",
            r"\bstdin\b|input\s*\(",
            r"\bread\s*\(",
            r"\bfread\s*\(",
            r"\brecv\s*\(",
            r"\bgetenv\s*\(",
        ]

    @staticmethod
    def _builtin_sanitizers() -> list[str]:
        return [
            r"escape\s*\(",
            r"sanitize",
            r"validate",
            r"realpath\s*\(",
            r"snprintf\s*\(",
            r"strncpy\s*\(",
            r"parameterized",
        ]

    def analyze(
        self,
        target: Path,
        dangerous_functions: list[DangerousFunction],
        semantic_index: SemanticIndex,
        llm_client: DeepSeekClient,
        budget: AuditBudget | None = None,
        strategy: MiningStrategy | None = None,
    ) -> list[ProgramSlice]:
        slices: list[ProgramSlice] = []
        max_slices = budget.max_slices if budget else 160
        ordered_anchors = self._order_anchors(dangerous_functions, strategy)
        for anchor in ordered_anchors[:max_slices]:
            if anchor.kind in self.STATIC_KINDS:
                slices.append(self._static_slice(anchor))
                continue
            path = target / anchor.file_path
            try:
                lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            start, end = self._bounds_for_file(path, lines, anchor.line_start)
            context_lines = [(idx, lines[idx - 1]) for idx in range(start, min(end, len(lines)) + 1)]
            context = "\n".join(f"{idx}: {text}" for idx, text in context_lines)
            source = self._infer_source(context)
            # Tool-verified findings (cppcheck, clang-tidy) may not match our web/Python-centric
            # source patterns.  Fall back to a tool-attributed source so downstream validators
            # don't discard real C/C++ bugs just because the "source" looks unfamiliar.
            if not source and anchor.tool_run_refs:
                source = f"tool_verified({anchor.tool})"
            guards = [text.strip() for _, text in context_lines if re.search(r"\b(if|while|for|switch|case|assert)\b", text)]
            sanitizers = [text.strip() for _, text in context_lines if self._has_any(text, self.SANITIZER_PATTERNS)]
            definitions = [text.strip() for _, text in context_lines if re.search(r"\b\w+\s*=\s*.+", text)]
            sink_line = lines[anchor.line_start - 1] if 1 <= anchor.line_start <= len(lines) else anchor.snippet
            sink_args = self._extract_args(sink_line)
            parameters = self._infer_parameters(lines, start, end)

            # --- C/C++ local data-flow enrichment (Phase D) ---
            file_suffix = path.suffix.lower()
            if file_suffix in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"} and hasattr(self, "GUARD_PATTERNS"):
                df = CppLocalDataFlowAnalyzer()
                source_vars = [source] if source else []
                df_result = df.analyze(lines[start - 1:end], anchor.line_start - start + 1, source_vars)
                # Enrich guards with data-flow facts
                for g in df_result.get("guards_before_sink", []):
                    if g.get("has_source"):
                        guards.append(f"[dataflow] {g['condition']} (line {g['line']})")
                # Add size/offset/index vars as contextual evidence
                size_vars = df_result.get("size_vars", [])
                offset_vars = df_result.get("offset_vars", [])
                if size_vars or offset_vars:
                    definitions.append(f"[dataflow] size_vars={','.join(size_vars[:5])} offset_vars={','.join(offset_vars[:5])}")
                # Better sink_args from data flow
                df_sink_args = df_result.get("sink_args", [])
                if df_sink_args:
                    sink_args = list(dict.fromkeys(sink_args + df_sink_args))[:10]

            missing_guards = self._missing_guards(anchor, source, guards, sanitizers)
            # Add parser-entry context for C/C++
            if hasattr(self, "parser_entry_patterns"):
                for pe_pat in self.parser_entry_patterns:
                    if re.search(pe_pat, anchor.function_name or "", re.IGNORECASE):
                        if "parser entry" not in missing_guards:
                            missing_guards.append(f"parser_entry_matched:{pe_pat}")
                        break
            call_chain = self._call_chain(anchor, semantic_index)
            data_flow = [item for item in [source or "unknown_input", anchor.function_name or anchor.file_path, anchor.sink] if item]
            excerpt = "\n".join(text for _, text in context_lines)
            slices.append(
                ProgramSlice(
                    id=self._id(anchor.id, excerpt),
                    dangerous_function_id=anchor.id,
                    file_path=anchor.file_path,
                    line_start=anchor.line_start,
                    function_name=anchor.function_name,
                    source=source,
                    sink=anchor.sink or anchor.dangerous_api,
                    controls=guards[:10],
                    parameters=parameters[:12],
                    sink_args=sink_args[:8],
                    definitions=definitions[:12],
                    call_chain=call_chain,
                    data_flow=data_flow,
                    guards=guards[:10],
                    missing_guards=missing_guards,
                    sanitizers=sanitizers[:10],
                    tool_evidence_ids=[anchor.rule_id],
                    tool_run_refs=list(anchor.tool_run_refs),
                    artifact_refs=list(anchor.artifact_refs),
                    context=context,
                    code_excerpt=excerpt[:2000],
                    llm_summary=self._deterministic_summary(anchor, source, guards, sanitizers, missing_guards),
                    rule_vuln_type=anchor.rule_vuln_type,
                    anchor_kind=anchor.kind,
                    anchor_category=anchor.anchor_category,
                    anchor_tool=anchor.tool,
                    anchor_confidence=anchor.confidence,
                )
            )
        return slices

    def _order_anchors(
        self,
        dangerous_functions: list[DangerousFunction],
        strategy: MiningStrategy | None,
    ) -> list[DangerousFunction]:
        if not strategy:
            return dangerous_functions

        def score(anchor: DangerousFunction) -> tuple[int, float]:
            value = 0
            path = (anchor.file_path or "").replace("\\", "/")
            function = anchor.function_name or ""
            for directory in strategy.focus_directories:
                prefix = directory.rstrip("/")
                if prefix in {"", "."} or path.startswith(prefix + "/") or path == prefix:
                    value += 3
                    break
            if function and any(item.lower() in function.lower() for item in strategy.priority_functions):
                value += 8
            if function and any(item.lower() in function.lower() for item in strategy.parser_entries):
                value += 6
            if function and any(item.lower() in function.lower() for item in strategy.dynamic_priority_functions):
                value += 5
            return (value, anchor.confidence)

        return sorted(dangerous_functions, key=score, reverse=True)

    def _static_slice(self, anchor: DangerousFunction) -> ProgramSlice:
        context = "\n".join(anchor.evidence + [anchor.snippet])
        source_by_kind = {
            "dependency_vulnerability": "dependency manifest",
            "secret_leak": "source literal",
            "configuration_security": "configuration file",
        }
        return ProgramSlice(
            id=self._id(anchor.id, context),
            dangerous_function_id=anchor.id,
            file_path=anchor.file_path,
            line_start=anchor.line_start,
            function_name=anchor.function_name,
            source=source_by_kind.get(anchor.kind, "static evidence"),
            sink=anchor.sink or anchor.dangerous_api,
            call_chain=[anchor.tool, anchor.function_name or anchor.file_path, anchor.dangerous_api],
            data_flow=[anchor.tool, anchor.function_name or anchor.file_path, anchor.dangerous_api],
            guards=[],
            missing_guards=[],
            sanitizers=[],
            tool_evidence_ids=[anchor.rule_id],
            tool_run_refs=list(anchor.tool_run_refs),
            artifact_refs=list(anchor.artifact_refs),
            context=context,
            code_excerpt=context[:2000],
            llm_summary=context[:400],
            rule_vuln_type=anchor.rule_vuln_type,
            anchor_kind=anchor.kind,
            anchor_category=anchor.anchor_category,
            anchor_tool=anchor.tool,
            anchor_confidence=anchor.confidence,
        )

    def _bounds_for_file(self, path: Path, lines: list[str], line_number: int) -> tuple[int, int]:
        suffix = path.suffix.lower()
        if suffix == ".py":
            bounds = self._python_bounds(path, line_number)
        elif suffix in {".js", ".jsx", ".ts", ".tsx"}:
            bounds = self._js_ts_bounds(path, line_number, lines)
        elif suffix in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}:
            bounds = self._cpp_bounds(path, line_number, lines)
        else:
            bounds = None
        if bounds:
            return bounds
        return max(1, line_number - 20), min(len(lines), line_number + 20)

    def _python_bounds(self, path: Path, line_number: int) -> tuple[int, int] | None:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, SyntaxError):
            return None
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = int(node.lineno)
                end = int(getattr(node, "end_lineno", node.lineno))
                if start <= line_number <= end:
                    return start, end
        return None

    def _js_ts_bounds(self, path: Path, line_number: int, lines: list[str]) -> tuple[int, int] | None:
        tree_sitter_bounds = self._js_ts_bounds_with_tree_sitter(path, line_number)
        if tree_sitter_bounds:
            return tree_sitter_bounds
        for index in range(line_number - 1, max(-1, line_number - 80), -1):
            line = lines[index]
            if re.search(r"(?:function|const|let|var)\s+[A-Za-z_][A-Za-z0-9_]*", line):
                return index + 1, min(len(lines), line_number + 20)
        return None

    def _js_ts_bounds_with_tree_sitter(self, path: Path, line_number: int) -> tuple[int, int] | None:
        try:
            import tree_sitter_languages  # type: ignore
        except ImportError:
            return None
        try:
            parser = tree_sitter_languages.get_parser("javascript")
            tree = parser.parse(path.read_bytes())
        except Exception:
            return None
        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            start = node.start_point[0] + 1
            end = node.end_point[0] + 1
            if node.type in {"function_declaration", "method_definition"} and start <= line_number <= end:
                return start, end
            stack.extend(node.children)
        return None

    def _cpp_bounds(self, path: Path, line_number: int, lines: list[str]) -> tuple[int, int] | None:
        # Try ctags: host first, then sandbox docker exec
        ctags = shutil.which("ctags")
        if not ctags:
            try:
                proc = subprocess.run(
                    ["docker", "exec", os.getenv("AUDIT_SANDBOX_CONTAINER", "agentic-code-audit-sandbox"), "which", "ctags"],
                    text=True, capture_output=True, timeout=5, check=False,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    ctags = "docker-exec-sandbox-ctags"
            except (OSError, subprocess.TimeoutExpired):
                pass
        if ctags:
            try:
                if ctags == "docker-exec-sandbox-ctags":
                    sandbox_path = str(path).replace("\\", "/")
                    for host_pfx, sbx_pfx in [("/app/", "/workspace/")]:
                        if sandbox_path.startswith(host_pfx):
                            sandbox_path = sbx_pfx + sandbox_path[len(host_pfx):]
                            break
                    proc = subprocess.run(
                        ["docker", "exec", os.getenv("AUDIT_SANDBOX_CONTAINER", "agentic-code-audit-sandbox"), "ctags", "-x", "--c-kinds=f", sandbox_path],
                        text=True, encoding="utf-8", errors="replace",
                        capture_output=True, timeout=10, check=False,
                    )
                else:
                    proc = subprocess.run(
                        [ctags, "-x", "--c-kinds=f", str(path)],
                        text=True, encoding="utf-8", errors="replace",
                        capture_output=True, timeout=10, check=False,
                    )
            except (OSError, subprocess.TimeoutExpired):
                proc = None
            if proc and proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 3 and parts[2].isdigit():
                        start = int(parts[2])
                        end = start + 50
                        if start <= line_number <= end:
                            return start, min(len(lines), end)
        for index in range(line_number - 1, max(-1, line_number - 120), -1):
            line = lines[index]
            if re.search(r"(?:[\w:<>\*&]+\s+)+[A-Za-z_~][A-Za-z0-9_:~]*\s*\([^;{}]*\)\s*(?:\{|$)", line):
                return index + 1, min(len(lines), line_number + 40)
        return None

    def _infer_source(self, context: str) -> str:
        for pattern in self.SOURCE_PATTERNS:
            match = re.search(pattern, context, flags=re.IGNORECASE)
            if match:
                return match.group(0)
        return ""

    def _infer_parameters(self, lines: list[str], start: int, end: int) -> list[str]:
        for index in range(start - 1, min(end, len(lines))):
            line = lines[index]
            match = re.search(r"\(([^)]*)\)", line)
            if match and any(token in line for token in ("def ", "function ", "func ", "fn ", "{")):
                return [part.strip() for part in match.group(1).split(",") if part.strip()]
        return []

    def _extract_args(self, line: str) -> list[str]:
        match = re.search(r"\((.*)\)", line)
        if not match:
            return []
        value = match.group(1)
        return [part.strip() for part in value.split(",") if part.strip()]

    def _missing_guards(
        self,
        anchor: DangerousFunction,
        source: str,
        guards: list[str],
        sanitizers: list[str],
    ) -> list[str]:
        if anchor.kind in self.STATIC_KINDS:
            return []
        missing: list[str] = []
        if source and not guards:
            missing.append("input validation")
        if anchor.category in {"command", "sql", "file"} and not sanitizers:
            missing.append("sanitization or allowlist")
        if anchor.category == "memory" and not any("length" in item.lower() or "size" in item.lower() for item in guards):
            missing.append("length or bounds check")
        return list(dict.fromkeys(missing))[:4]

    def _call_chain(self, anchor: DangerousFunction, semantic_index: SemanticIndex) -> list[str]:
        for route in semantic_index.routes:
            if route.file_path == anchor.file_path and route.line_start <= anchor.line_start:
                return [f"{route.method} {route.route}", route.handler, anchor.function_name or anchor.file_path, anchor.sink]
        callers = [
            item.name
            for item in semantic_index.functions
            if item.file_path == anchor.file_path and item.name and item.name != anchor.function_name
        ][:3]
        chain = callers + [anchor.function_name or anchor.file_path, anchor.sink]
        return [item for item in chain if item]

    def _deterministic_summary(
        self,
        anchor: DangerousFunction,
        source: str,
        guards: list[str],
        sanitizers: list[str],
        missing_guards: list[str],
    ) -> str:
        source_text = source or "no clear user-controlled source was found in the local slice"
        guard_text = "guards present" if guards else "guards not observed"
        sanitizer_text = "sanitizer present" if sanitizers else "sanitizer not observed"
        missing_text = ", ".join(missing_guards) or "none"
        return f"{source_text}; sink={anchor.sink or anchor.dangerous_api}; {guard_text}; {sanitizer_text}; missing={missing_text}."

    def _has_any(self, text: str, patterns: list[str]) -> bool:
        return any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns)

    def _id(self, anchor_id: str, context: str) -> str:
        return hashlib.sha1(f"{anchor_id}:{context[:240]}".encode("utf-8")).hexdigest()[:12]


# ---------------------------------------------------------------------------
# C/C++ function-local data-flow analyser (Phase D)
# ---------------------------------------------------------------------------

class CppLocalDataFlowAnalyzer:
    """Lightweight, function-local data-flow analysis for C/C++.

    Does NOT perform inter-procedural or whole-program analysis.
    Identifies size/offset/index variables, guard expressions, and
    whether a guard dominates a given sink line.
    """

    def analyze(self, lines: list[str], sink_line: int, source_vars: list[str]) -> dict[str, Any]:
        """Analyse *lines* and return structured data-flow facts."""
        result: dict[str, Any] = {
            "definitions": [],
            "assignments": [],
            "size_vars": [],
            "offset_vars": [],
            "index_vars": [],
            "guard_expressions": [],
            "guards_before_sink": [],
            "sink_args": [],
            "aliases": [],
        }

        # Collect definitions / assignments / guards / sink args
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("//", "/*", "*", "#")):
                continue
            # Variable definitions (simplified: type identifier = ...)
            def_match = re.match(
                r"(?:const\s+)?(?:unsigned\s+)?(?:size_t|int|long|uint\w*|auto)\s+(\w+)\s*[=;]",
                stripped,
            )
            if def_match:
                var = def_match.group(1)
                result["definitions"].append({"var": var, "line": idx})
                if any(kw in var.lower() for kw in ("size", "len", "length", "count", "num", "total", "max", "capacity")):
                    result["size_vars"].append(var)
                if any(kw in var.lower() for kw in ("offset", "pos", "start", "begin", "seek")):
                    result["offset_vars"].append(var)
                if any(kw in var.lower() for kw in ("idx", "index", "i", "j", "k")):
                    result["index_vars"].append(var)

            # Variable assignment (simplified: identifier = expression)
            assign_match = re.match(r"(\w+)\s*=\s*(.+);", stripped)
            if assign_match:
                var, expr = assign_match.group(1), assign_match.group(2)
                result["assignments"].append({"var": var, "expr": expr, "line": idx})
                # Detect aliases / pointer references
                if "&" in expr or var.startswith("p") or "Ptr" in var:
                    result["aliases"].append({"var": var, "expr": expr, "line": idx})

            # Guard expressions (if/while/for conditions before sink)
            guard_match = re.match(r"(?:if|while|for)\s*\((.+)\)", stripped)
            if guard_match and idx < sink_line:
                condition = guard_match.group(1)
                result["guard_expressions"].append({"condition": condition, "line": idx})
                contains_source = any(sv in condition for sv in source_vars)
                if contains_source:
                    result["guards_before_sink"].append({"condition": condition, "line": idx, "has_source": True})

            # Sink arguments (extract args from the sink line)
            if idx == sink_line:
                args_match = re.search(r"\((.*)\)", stripped)
                if args_match:
                    args = [a.strip() for a in args_match.group(1).split(",") if a.strip()]
                    result["sink_args"] = args

        return result


# ---------------------------------------------------------------------------
# CandidateGenerator
# ---------------------------------------------------------------------------

class CandidateGenerator:
    def __init__(
        self,
        cwe_mapping: dict[str, str] | None = None,
        normalizer: VulnerabilityTypeNormalizer | None = None,
        llm_client: DeepSeekClient | None = None,
    ) -> None:
        self.cwe_mapping = cwe_mapping or dict(RulesLoader().load().get("common.cwe_mapping") or {})
        self.normalizer = normalizer or VulnerabilityTypeNormalizer()
        self.reviewer = LLMCandidateReviewer(llm_client) if llm_client else None
        self.llm_calls_used = 0

    def generate(
        self,
        slices: list[ProgramSlice],
        llm_client: DeepSeekClient,
        budget: AuditBudget | None = None,
    ) -> list[VulnerabilityCandidate]:
        """Generate candidates from slices, using different strategies for tool vs rules anchors.

        - **Tool-anchor slices** (semgrep, cppcheck, clang-tidy): full LLM generation
          because the tool output is richer and LLM can interpret it contextually.
        - **Rules-anchor slices** (regex-matched memcpy, strcpy, etc.): fast deterministic
          path using _fallback_candidate().  The sink is already known and the normalizer
          maps it to a VulnType.  No LLM call needed per slice.
        """
        candidates: list[VulnerabilityCandidate] = []
        tool_slices: list[ProgramSlice] = []
        rule_slices: list[ProgramSlice] = []
        self.llm_calls_used = 0
        max_candidates = budget.max_candidates if budget else 200
        max_llm_calls = budget.max_llm_calls if budget else 999_999

        for program_slice in slices[:max_candidates]:
            # Slices with tool evidence → LLM path; pure rule matches → fast path
            if program_slice.anchor_tool == "rules" and not program_slice.tool_run_refs:
                rule_slices.append(program_slice)
            else:
                tool_slices.append(program_slice)

        # --- Fast path: rules-based slices (no LLM per slice) ---
        for program_slice in rule_slices:
            candidates.append(self._fallback_candidate(program_slice))

        # --- LLM path: tool-based slices (batch generation + parallel) ---
        if tool_slices:
            grouped: dict[tuple[str, str], list[ProgramSlice]] = {}
            for program_slice in tool_slices:
                inferred = self._type_from_sink(program_slice.sink)
                grouped.setdefault((self._language(program_slice.file_path), inferred), []).append(program_slice)

            # Build all batches
            batches: list[list[ProgramSlice]] = []
            for (_lang, _vt), group in grouped.items():
                batch_size = max(3, min(4, 8))
                for i in range(0, len(group), batch_size):
                    batches.append(group[i : i + batch_size])
            if len(batches) > max_llm_calls:
                batches = batches[:max_llm_calls]

            # Parallelize LLM batch calls (I/O-bound — ThreadPoolExecutor)
            batch_results: list[tuple[int, list[dict[str, Any]]]] = []
            if len(batches) > 1 and llm_client.enabled:
                with ThreadPoolExecutor(max_workers=min(4, len(batches))) as ex:
                    future_to_idx = {
                        ex.submit(self._ask_llm_batch, batch, llm_client): i
                        for i, batch in enumerate(batches)
                    }
                    for future in as_completed(future_to_idx):
                        idx = future_to_idx[future]
                        try:
                            batch_results.append((idx, future.result()))
                        except Exception:
                            batch_results.append((idx, []))
                # Sort back to original order
                batch_results.sort(key=lambda x: x[0])
            else:
                for i, batch in enumerate(batches):
                    batch_results.append((i, self._ask_llm_batch(batch, llm_client)))

            for batch_idx, (batch, llm_result) in enumerate(zip(batches, [r[1] for r in batch_results])):
                for slice_idx, program_slice in enumerate(batch):
                    raw = llm_result[slice_idx] if slice_idx < len(llm_result) else None
                    candidate = self._candidate_from_raw(program_slice, raw) if raw else self._fallback_candidate(program_slice)
                    candidates.append(candidate)

        # LLM quality gate — review suspicious candidates (tool-based + low-confidence rule-based)
        if self.reviewer and self.llm_calls_used < max_llm_calls:
            self.reviewer.max_llm_calls = max_llm_calls - self.llm_calls_used
            candidates = self.reviewer.review_batch(candidates, llm_client)
            self.llm_calls_used += self.reviewer.llm_calls_used

        return candidates[:max_candidates]

    def _ask_llm_batch(self, slices: list[ProgramSlice], llm_client: DeepSeekClient) -> list[dict[str, Any]]:
        if not hasattr(llm_client, "chat"):
            return []
        self.llm_calls_used += 1
        prompt = (
            "Return a JSON array of vulnerability candidates. Each item must map to the corresponding slice index and "
            "include file, function, line, sink, trigger_condition, title, vulnerability_type, severity, description, "
            "trigger_conditions, evidence, missing_checks, assumptions, confidence, valid."
        )
        user = json.dumps([slice_.__dict__ for slice_ in slices], ensure_ascii=False)
        response = llm_client.chat(prompt, user, timeout=45)
        if not getattr(response, "ok", False):
            return []
        text = str(getattr(response, "content", "") or "").strip()
        try:
            raw = json.loads(text)
        except json.JSONDecodeError:
            match = re.search(r"\[.*\]", text, flags=re.S)
            if not match:
                return []
            try:
                raw = json.loads(match.group(0))
            except json.JSONDecodeError:
                return []
        return raw if isinstance(raw, list) else []

    def _candidate_from_raw(self, program_slice: ProgramSlice, raw: dict[str, Any]) -> VulnerabilityCandidate:
        # Normalize C++ std:: prefixes before type normalization
        raw_sink = str(program_slice.sink or "")
        normalized_sink = self._normalize_sink(raw_sink)
        if normalized_sink != raw_sink:
            program_slice.sink = normalized_sink

        vuln_type = self.normalizer.normalize(
            llm_type=str(raw.get("vulnerability_type") or ""),
            rule_vuln_type=program_slice.rule_vuln_type,
            anchor_category=program_slice.anchor_category,
            sink=program_slice.sink,
            file_path=program_slice.file_path,
            category=program_slice.anchor_category,
        ).value
        trigger_conditions = coerce_str_list(raw.get("trigger_conditions") or raw.get("trigger_condition"))[:8]

        # Detect LLM self-identified false positives from the title
        title = str(raw.get("title") or "")
        if re.search(r"^\s*false\s*positive", title, re.IGNORECASE):
            return self._fallback_candidate(program_slice, reject_reason=f"LLM self-identified false positive: {title[:120]}")

        valid, validity, invalid_reason = self._validate_candidate(program_slice, trigger_conditions)
        risk_domain = risk_domain_for(VulnType.from_string(vuln_type)).value
        return VulnerabilityCandidate(
            id=self._id(program_slice.id, str(raw.get("title") or vuln_type)),
            slice_id=program_slice.id,
            title=str(raw.get("title") or self._default_title(program_slice, vuln_type)),
            vulnerability_type=vuln_type,
            severity=str(raw.get("severity") or self._severity_for(vuln_type)),
            file_path=program_slice.file_path,
            line_start=program_slice.line_start,
            description=str(raw.get("description") or ""),
            function_name=program_slice.function_name,
            trigger_conditions=trigger_conditions[:8],
            evidence=coerce_str_list(raw.get("evidence"))[:12],
            cwe=self.cwe_mapping.get(vuln_type, ""),
            sink=program_slice.sink,
            source=program_slice.source,
            missing_checks=coerce_str_list(raw.get("missing_checks"))[:8],
            assumptions=coerce_str_list(raw.get("assumptions"))[:8],
            evidence_refs=[program_slice.id, *program_slice.tool_run_refs, *program_slice.artifact_refs],
            confidence=self._parse_confidence(raw.get("confidence")),
            valid=valid,
            validity=validity,
            llm_reasoning=str(raw.get("llm_reasoning") or ""),
            candidate_source="llm",
            invalid_reason=invalid_reason,
            risk_domain=risk_domain,
        )

    @staticmethod
    def _normalize_sink(sink: str) -> str:
        """Normalize C++ std:: prefix variants to canonical sink names.

        std::memcpy → memcpy, std::strcpy → strcpy, etc.
        This prevents duplicate findings for the same vulnerability.
        """
        if not sink:
            return sink
        # Strip std:: prefix
        normalized = re.sub(r'^std::', '', sink.strip())
        # Also normalize common C++ variants
        normalized = normalized.strip()
        return normalized

    def _fallback_candidate(
        self, program_slice: ProgramSlice, reject_reason: str = ""
    ) -> VulnerabilityCandidate:
        # Normalize C++ std:: prefix to prevent duplicate findings
        raw_sink = str(program_slice.sink or "")
        normalized_sink = self._normalize_sink(raw_sink)
        if normalized_sink != raw_sink:
            program_slice.sink = normalized_sink
        vuln_type = self.normalizer.normalize(
            rule_vuln_type=program_slice.rule_vuln_type,
            anchor_category=program_slice.anchor_category,
            sink=program_slice.sink,
            file_path=program_slice.file_path,
            category=program_slice.anchor_category,
        ).value
        trigger_conditions = [program_slice.source] if program_slice.source else []
        if reject_reason:
            valid, validity, invalid_reason = False, "invalid_candidate", reject_reason
        else:
            valid, validity, invalid_reason = self._validate_candidate(program_slice, trigger_conditions)
        risk_domain = risk_domain_for(VulnType.from_string(vuln_type)).value
        return VulnerabilityCandidate(
            id=self._id(program_slice.id, vuln_type),
            slice_id=program_slice.id,
            title=self._default_title(program_slice, vuln_type),
            vulnerability_type=vuln_type,
            severity=self._severity_for(vuln_type),
            file_path=program_slice.file_path,
            line_start=program_slice.line_start,
            description=program_slice.llm_summary or f"Conservative candidate for {vuln_type}.",
            function_name=program_slice.function_name,
            trigger_conditions=trigger_conditions or ["attacker-controlled input reaches the sink"],
            evidence=[program_slice.llm_summary, f"source={program_slice.source}", f"sink={program_slice.sink}"],
            cwe=self.cwe_mapping.get(vuln_type, ""),
            sink=program_slice.sink,
            source=program_slice.source,
            missing_checks=list(program_slice.missing_guards),
            assumptions=["fallback_candidate"] if not reject_reason else [reject_reason],
            evidence_refs=[program_slice.id, *program_slice.tool_run_refs, *program_slice.artifact_refs],
            confidence=0.48,
            valid=valid,
            validity=validity,
            llm_reasoning=program_slice.llm_summary,
            candidate_source="rule",
            invalid_reason=invalid_reason,
            risk_domain=risk_domain,
        )

    def _validate_candidate(self, program_slice: ProgramSlice, trigger_conditions: list[str]) -> tuple[bool, str, str]:
        """Return (valid, validity, invalid_reason)."""
        static_sources = {"dependency manifest", "source literal", "configuration file", "static evidence"}
        # Tool findings (cppcheck, clang-tidy, etc.) carry their own evidence via tool_run_refs.
        # They don't need a human-readable function_name or source to be valid — the tool
        # already verified the file, line, and check.  This prevents real C/C++ bugs from
        # being discarded just because we can't infer a "source" from regex patterns.
        has_tool_evidence = bool(program_slice.tool_run_refs)
        has_required_context = (
            bool(program_slice.function_name)
            or program_slice.source in static_sources
            or has_tool_evidence
        )
        reasons: list[str] = []
        if not program_slice.file_path:
            reasons.append("missing_file_path")
        if not program_slice.line_start:
            reasons.append("missing_line_start")
        if not program_slice.sink:
            reasons.append("missing_sink")
        if not has_required_context:
            if not program_slice.function_name:
                reasons.append("missing_function_name")
            if program_slice.source not in static_sources and not has_tool_evidence:
                reasons.append("missing_source_or_static_context")
        if not trigger_conditions:
            reasons.append("missing_trigger_condition")
        if self._is_unsupported_weak_cpp_candidate(program_slice):
            reasons.append("weak_cpp_rule_without_strong_condition")
        if not reasons:
            return (True, "valid", "")
        return (False, "invalid_candidate", ";".join(reasons))

    def _is_unsupported_weak_cpp_candidate(self, program_slice: ProgramSlice) -> bool:
        if program_slice.anchor_tool != "rules":
            return False
        if program_slice.anchor_category not in {"", "source_code"}:
            return False
        sink = (program_slice.sink or "").strip()
        if sink not in WEAK_CPP_APIS and program_slice.anchor_confidence >= 0.50:
            return False
        has_tool_evidence = bool(program_slice.tool_run_refs)
        has_source_sink_guard = bool(program_slice.source and program_slice.sink and program_slice.missing_guards)
        context = f"{program_slice.function_name} {program_slice.file_path}".lower()
        has_parser_context = any(token in context for token in ("read", "decode", "parse", "load", "writemetadata", "metadata"))
        has_combo_rule = (
            sink in {"memcpy", "memmove", "std::copy", "copy"}
            and bool(program_slice.sink_args)
            and any("bound" in item.lower() or "length" in item.lower() for item in program_slice.missing_guards)
        )
        return not (has_tool_evidence or has_source_sink_guard or has_parser_context or has_combo_rule)

    def _parse_confidence(self, value: Any) -> float:
        if value is None or value == "":
            return 0.5
        if isinstance(value, bool):
            return 0.7 if value else 0.3
        if isinstance(value, (int, float)):
            numeric = float(value)
            if numeric > 1:
                numeric = numeric / 100
            return max(0.0, min(1.0, numeric))
        text = str(value).strip().lower()
        labels = {
            "critical": 0.9,
            "very high": 0.85,
            "high": 0.8,
            "medium": 0.6,
            "moderate": 0.6,
            "low": 0.35,
            "weak": 0.3,
            "none": 0.0,
        }
        if text in labels:
            return labels[text]
        if text.endswith("%"):
            text = text[:-1].strip()
        try:
            numeric = float(text)
        except ValueError:
            return 0.5
        if numeric > 1:
            numeric = numeric / 100
        return max(0.0, min(1.0, numeric))

    def _default_title(self, program_slice: ProgramSlice, vuln_type: str) -> str:
        return f"{program_slice.function_name or program_slice.file_path} may expose {vuln_type}"

    def _type_from_sink(self, sink: str) -> str:
        vuln_type = self.normalizer.normalize(sink=sink)
        return vuln_type.value

    def _severity_for(self, vuln_type: str) -> str:
        if vuln_type in {"command_injection", "code_execution", "unsafe_c_string_api",
                         "unsafe_memory_copy", "out_of_bounds_write", "use_after_free",
                         "double_free"}:
            return "high"
        if vuln_type in {"sql_injection", "deserialization", "integer_overflow",
                         "out_of_bounds_read", "null_dereference", "path_traversal"}:
            return "medium"
        if vuln_type == "supply_chain_config":
            return "medium"
        if vuln_type in {"resource_leak", "weak_static_proof"}:
            return "low"
        return "low"

    def _language(self, file_path: str) -> str:
        suffix = Path(file_path).suffix.lower()
        return {
            ".py": "Python",
            ".js": "JavaScript",
            ".jsx": "JavaScript",
            ".ts": "TypeScript",
            ".tsx": "TypeScript",
            ".c": "C",
            ".cc": "C++",
            ".cpp": "C++",
            ".cxx": "C++",
            ".go": "Go",
            ".rs": "Rust",
        }.get(suffix, "unknown")

    def _id(self, slice_id: str, title: str) -> str:
        return hashlib.sha1(f"{slice_id}:{title}".encode("utf-8")).hexdigest()[:12]


class LLMCandidateReviewer:
    """LLM-powered quality gate for vulnerability candidates.

    Reviews candidates in batches, asking the LLM to distinguish real security
    vulnerabilities from config-lint / best-practice / tool-noise findings.
    Rejected candidates get valid=False so ClueAggregator drops them.
    """

    REVIEW_PROMPT = """你是资深安全审计专家。请审查以下漏洞候选，判断它是否是一个**真实的安全漏洞**。

审查要点:
1. 这个 sink 在该上下文中是否真的危险（能导致可利用的安全后果）？
2. 这是**代码漏洞**还是**配置规范建议**？
3. 如果候选的文件是 CI 配置（YAML JSON TOML），且 sink 是 lint 规则匹配，这是配置检查而非漏洞
4. 如果是 dependency/package 相关的发现，检查是否有已知 CVE 或具体风险描述

对每个候选输出 JSON 数组:
[{"verdict": "confirmed|rejected", "reasoning": "简短理由"}]

- confirmed: 这是一个需要关注的安全漏洞
- rejected: 这是配置lint、代码风格、或不构成实际安全威胁的发现"""

    def __init__(self, llm_client: DeepSeekClient | None = None):
        self.llm_client = llm_client
        self.max_llm_calls = 999_999
        self.llm_calls_used = 0

    def review_batch(
        self,
        candidates: list[VulnerabilityCandidate],
        llm_client: DeepSeekClient,
    ) -> list[VulnerabilityCandidate]:
        """Review a list of candidates. Returns the same list with invalid ones flagged."""
        if not self.llm_client:
            self.llm_client = llm_client

        to_review = [c for c in candidates if self._needs_review(c)]
        if not to_review:
            return candidates

        # Review in small batches (max 3 per call)
        self.llm_calls_used = 0
        for batch_start in range(0, len(to_review), 3):
            if self.llm_calls_used >= self.max_llm_calls:
                break
            batch = to_review[batch_start : batch_start + 3]
            judgments = self._ask_llm(batch)
            for candidate, judgment in zip(batch, judgments):
                verdict = str(judgment.get("verdict", "")).lower()
                reasoning = str(judgment.get("reasoning", ""))
                if verdict == "rejected":
                    candidate.mark_invalid(f"llm_rejected({reasoning[:120]})" if reasoning else "llm_rejected")
                elif verdict == "confirmed":
                    # Boost confidence for LLM-confirmed candidates
                    candidate.confidence = min(0.95, candidate.confidence + 0.08)

        return candidates

    def _needs_review(self, candidate: VulnerabilityCandidate) -> bool:
        """Only review the most suspicious candidates to minimize LLM calls."""
        if not candidate.valid:
            return False
        vt = (candidate.vulnerability_type or "").lower()
        # Only review supply_chain_config that have vague titles (likely config lint noise)
        if vt == "supply_chain_config":
            title = (candidate.title or "").lower()
            noise_keywords = ["github-actions", "mutable", "dependabot", "workflow", "other"]
            return any(kw in title for kw in noise_keywords)
        # Only review dependency findings with no CVE reference
        if vt == "dependency_vulnerability":
            return not any("cve" in str(e).lower() for e in candidate.evidence)
        return False

    def _ask_llm(self, candidates: list[VulnerabilityCandidate]) -> list[dict[str, Any]]:
        """Ask LLM to review a batch of candidates."""
        self.llm_calls_used += 1
        items = []
        for i, c in enumerate(candidates):
            items.append({
                "index": i,
                "title": c.title,
                "type": c.vulnerability_type,
                "file": c.file_path,
                "line": c.line_start,
                "sink": c.sink,
                "source": c.source,
                "function": c.function_name,
                "description": (c.description or "")[:300],
                "evidence": [str(e)[:200] for e in (c.evidence or [])[:3]],
            })

        prompt = self.REVIEW_PROMPT + "\n\n候选列表:\n" + json.dumps(items, ensure_ascii=False, indent=2)
        try:
            resp = self.llm_client.chat(
                "你是安全审计专家。只输出JSON数组，不要其他内容。",
                prompt,
                timeout=45,
            )
        except Exception:
            return [{"verdict": "confirmed", "reasoning": "LLM unavailable"}] * len(candidates)

        if not resp.ok or not resp.content.strip():
            return [{"verdict": "confirmed", "reasoning": "LLM error"}] * len(candidates)

        # Parse JSON array
        text = resp.content.strip()
        try:
            result = json.loads(text)
        except json.JSONDecodeError:
            match = re.search(r"\[.*\]", text, re.S)
            if match:
                try:
                    result = json.loads(match.group(0))
                except json.JSONDecodeError:
                    return [{"verdict": "confirmed", "reasoning": "parse error"}] * len(candidates)
            else:
                return [{"verdict": "confirmed", "reasoning": "parse error"}] * len(candidates)

        if isinstance(result, list) and len(result) == len(candidates):
            return result
        # Mismatch — accept all
        return [{"verdict": "confirmed", "reasoning": "result mismatch"}] * len(candidates)


class ClueAggregator:
    def aggregate(self, candidates: list[VulnerabilityCandidate]) -> list[VulnerabilityCandidate]:
        merged: dict[tuple, VulnerabilityCandidate] = {}
        trigger_counts: dict[tuple, int] = {}
        for candidate in candidates:
            if not candidate.valid or candidate.validity != "valid":
                continue
            # Aggregate key varies by risk domain
            vt = (candidate.vulnerability_type or "").lower()
            if vt in ("supply_chain_config",):
                key = (candidate.file_path, candidate.vulnerability_type, str(candidate.line_start), "")
            elif vt in ("dependency_vulnerability",):
                key = (candidate.function_name or candidate.file_path, candidate.vulnerability_type, candidate.sink or "", "")
            elif vt in ("secret_leak",):
                key = (candidate.file_path, candidate.sink or candidate.vulnerability_type, "", "")
            else:
                key = (
                    candidate.file_path,
                    candidate.function_name or "",
                    candidate.sink or candidate.vulnerability_type,
                    candidate.source or "",
                )
            trigger_counts[key] = trigger_counts.get(key, 0) + 1
            current = merged.get(key)
            if current is None:
                merged[key] = candidate
                continue
            current.evidence.extend(item for item in candidate.evidence if item not in current.evidence)
            current.trigger_conditions.extend(item for item in candidate.trigger_conditions if item not in current.trigger_conditions)
            current.missing_checks.extend(item for item in candidate.missing_checks if item not in current.missing_checks)
            current.assumptions.extend(item for item in candidate.assumptions if item not in current.assumptions)
            current.evidence_refs.extend(item for item in candidate.evidence_refs if item not in current.evidence_refs)
            current.confidence = min(0.95, max(current.confidence, candidate.confidence) + 0.04)
        for key, candidate in merged.items():
            strength = self._evidence_strength(candidate)
            candidate.assumptions.extend(
                [
                    f"evidence_strength={strength}",
                    f"trigger_paths={trigger_counts.get(key, 1)}",
                ]
            )
        return sorted(merged.values(), key=lambda item: item.confidence, reverse=True)

    def _evidence_strength(self, candidate: VulnerabilityCandidate) -> str:
        # Source weighting: tool > rule > llm
        source_bonus = {"tool": 0.08, "rule": 0.04, "llm": 0.0}.get(candidate.candidate_source, 0.0)
        adjusted = candidate.confidence + source_bonus
        if adjusted >= 0.75 or len(candidate.evidence) >= 4:
            return "strong"
        if adjusted >= 0.55 or len(candidate.evidence) >= 2:
            return "medium"
        return "weak"


class VulnerabilityClassifier:
    TAXONOMY = {
        "sql_injection": ("CWE-89", "A03:2021-Injection"),
        "command_injection": ("CWE-78", "A03:2021-Injection"),
        "path_traversal": ("CWE-22", "A01:2021-Broken Access Control"),
        "unsafe_memory_copy": ("CWE-787", "Memory Safety"),
        "unsafe_c_string_api": ("CWE-120", "Memory Safety"),
        "integer_overflow": ("CWE-190", "Memory Safety"),
        "out_of_bounds_read": ("CWE-125", "Memory Safety"),
        "out_of_bounds_write": ("CWE-787", "Memory Safety"),
        "use_after_free": ("CWE-416", "Memory Safety"),
        "double_free": ("CWE-415", "Memory Safety"),
        "null_dereference": ("CWE-476", "Memory Safety"),
        "resource_leak": ("CWE-404", "Memory Safety"),
        "code_execution": ("CWE-94", "A03:2021-Injection"),
        "deserialization": ("CWE-502", "A08:2021-Software and Data Integrity Failures"),
        "dependency_vulnerability": ("CWE-1104", "Vulnerable and Outdated Components"),
        "secret_leak": ("CWE-798", "A07:2021-Identification and Authentication Failures"),
        "supply_chain_config": ("CWE-829", "A08:2021-Software and Data Integrity Failures"),
        "weak_static_proof": ("", ""),
        "other": ("", ""),
    }

    def __init__(
        self,
        normalizer: VulnerabilityTypeNormalizer | None = None,
        llm_client: DeepSeekClient | None = None,
    ) -> None:
        self.normalizer = normalizer or VulnerabilityTypeNormalizer()
        self.llm_client = llm_client

    def classify(
        self,
        candidates: list[VulnerabilityCandidate],
        slices: list[ProgramSlice],
        llm_client: DeepSeekClient,
        budget: AuditBudget | None = None,
    ) -> list[Finding]:
        slices_by_id = {item.id: item for item in slices}
        findings: list[Finding] = []
        max_findings = budget.max_findings if budget else 80
        for candidate in candidates[:max_findings]:
            program_slice = slices_by_id.get(candidate.slice_id)
            if not program_slice:
                continue
            # Normalize type through the normalizer (never use raw LLM string)
            vuln_type = self.normalizer.normalize(
                llm_type=candidate.vulnerability_type,
                rule_vuln_type=program_slice.rule_vuln_type,
                anchor_category=program_slice.anchor_category or candidate.risk_domain,
                sink=program_slice.sink,
                file_path=candidate.file_path,
                category=program_slice.anchor_category or candidate.risk_domain,
            ).value
            vuln_type_enum = VulnType.from_string(vuln_type)
            risk_domain = risk_domain_for(vuln_type_enum).value
            cwe, owasp = self.TAXONOMY.get(vuln_type, ("", ""))
            score_breakdown = self._score(vuln_type, risk_domain, candidate, program_slice)
            total_score = sum(score_breakdown.values())
            severity = self._severity(total_score)
            # LLM-assisted severity review for source_code findings
            if self.llm_client and risk_domain == "source_code":
                llm_adj = self._llm_severity_assessment(candidate, program_slice, vuln_type)
                if llm_adj:
                    severity = llm_adj.get("severity", severity)
                    if llm_adj.get("reasoning"):
                        score_breakdown["llm_review"] = llm_adj["reasoning"][:100]
            evidence_strength = self._evidence_strength(total_score)
            should_verify = self._should_verify(vuln_type_enum, evidence_strength, total_score)
            summary = self._summary(candidate, program_slice, total_score, score_breakdown)
            graph = self._chain_graph(candidate, program_slice, vuln_type)
            findings.append(
                Finding(
                    id=candidate.id,
                    vulnerability_type=vuln_type,
                    severity=severity,
                    title=candidate.title,
                    description=candidate.description or summary,
                    file_path=candidate.file_path,
                    line_start=candidate.line_start,
                    code_snippet=program_slice.code_excerpt or program_slice.context,
                    source=program_slice.source,
                    sink=program_slice.sink,
                    call_chain=program_slice.call_chain,
                    evidence=[
                        *candidate.evidence,
                        summary,
                        f"score={total_score}",
                        f"director_priority={candidate.director_priority}",
                        f"director_reason={candidate.director_reason or 'n/a'}",
                        *[f"{k}={v}" for k, v in score_breakdown.items()],
                    ],
                    confidence=min(0.95, max(0.1, candidate.confidence + total_score / 20)),
                    needs_verification=should_verify,
                    evidence_strength=evidence_strength,
                    reachability=self._reachability(program_slice),
                    exploitability=self._exploitability(vuln_type),
                    should_verify=should_verify,
                    verification_reason=self._verification_reason(vuln_type, evidence_strength, total_score),
                    tool="vulnerability-mining-agent",
                    recommendation=self._recommendation(vuln_type),
                    exploit_payloads=self._payloads_for(vuln_type),
                    exploit_chain=[node.label for node in graph.nodes],
                    cwe=cwe or candidate.cwe,
                    owasp=owasp,
                    function_name=program_slice.function_name,
                    trigger_conditions=candidate.trigger_conditions,
                    slice_id=program_slice.id,
                    candidate_id=candidate.id,
                    dangerous_function_id=program_slice.dangerous_function_id,
                    tool_run_refs=list(program_slice.tool_run_refs),
                    artifact_refs=list(program_slice.artifact_refs),
                    chain_graph=graph,
                    chinese_summary=summary,
                    risk_domain=risk_domain,
                    director_priority=candidate.director_priority,
                    director_reason=candidate.director_reason,
                    verification_hint=dict(candidate.verification_hint),
                )
            )
        return findings

    def _score(
        self,
        vuln_type: str,
        risk_domain: str,
        candidate: VulnerabilityCandidate,
        program_slice: ProgramSlice,
    ) -> dict[str, int]:
        """Compute a score breakdown appropriate to the risk domain."""
        if risk_domain == "supply_chain_config":
            return self._score_config(candidate)
        if risk_domain in ("dependency",):
            return self._score_dependency(candidate)
        if risk_domain in ("secret",):
            return self._score_secret(candidate)
        return self._score_source_code(vuln_type, candidate, program_slice)

    def _score_source_code(
        self,
        vuln_type: str,
        candidate: VulnerabilityCandidate,
        program_slice: ProgramSlice,
    ) -> dict[str, int]:
        sink_danger = {
            "command_injection": 3,
            "code_execution": 3,
            "unsafe_c_string_api": 3,
            "unsafe_memory_copy": 3,
            "out_of_bounds_write": 3,
            "use_after_free": 3,
            "double_free": 3,
            "sql_injection": 2,
            "path_traversal": 2,
            "deserialization": 2,
            "integer_overflow": 2,
            "out_of_bounds_read": 2,
            "null_dereference": 2,
            "resource_leak": 1,
            "dependency_vulnerability": 1,
            "secret_leak": 1,
            "supply_chain_config": 1,
            "weak_static_proof": 0,
            "other": 0,
        }.get(vuln_type, 1)
        source_control = 0
        if program_slice.source in {"dependency manifest", "source literal", "configuration file", "static evidence"}:
            source_control = 1
        elif program_slice.source:
            source_control = 3 if any(token in program_slice.source.lower() for token in ("request", "query", "body", "input", "argv", "recv")) else 2
        reachability = 3 if len(program_slice.call_chain) >= 3 else (2 if program_slice.call_chain else 1)
        missing_guards = min(2, len(program_slice.missing_guards))
        tool_corroboration = min(2, len(program_slice.tool_run_refs))
        return {
            "sink_danger": sink_danger,
            "source_control": source_control,
            "reachability": reachability,
            "missing_guards": missing_guards,
            "tool_corroboration": tool_corroboration,
        }

    def _score_config(self, candidate: VulnerabilityCandidate) -> dict[str, int]:
        """Scoring formula for supply_chain_config / CI-CD findings."""
        tool_corroboration = min(2, len(candidate.evidence_refs))
        rule_confidence = int(min(3, candidate.confidence * 4))
        asset_importance = 0
        fp = (candidate.file_path or "").lower()
        if ".github/workflows" in fp:
            asset_importance = 2
        elif "dependabot" in fp:
            asset_importance = 1
        exploit_precondition = 0
        if any("mutable" in e.lower() or "unpinned" in e.lower() for e in candidate.evidence):
            exploit_precondition = 2
        elif any("action" in e.lower() for e in candidate.evidence):
            exploit_precondition = 1
        return {
            "rule_confidence": rule_confidence,
            "asset_importance": asset_importance,
            "exploit_precondition": exploit_precondition,
            "tool_corroboration": tool_corroboration,
        }

    def _score_dependency(self, candidate: VulnerabilityCandidate) -> dict[str, int]:
        """Scoring formula for dependency_vulnerability findings."""
        tool_corroboration = min(2, len(candidate.evidence_refs))
        rule_confidence = int(min(3, candidate.confidence * 4))
        # Higher severity CVEs get higher importance
        sev = (candidate.severity or "").lower()
        asset_importance = {"critical": 2, "high": 2, "medium": 1, "low": 0}.get(sev, 1)
        return {
            "rule_confidence": rule_confidence,
            "asset_importance": asset_importance,
            "tool_corroboration": tool_corroboration,
        }

    def _score_secret(self, candidate: VulnerabilityCandidate) -> dict[str, int]:
        """Scoring formula for secret_leak findings."""
        tool_corroboration = min(2, len(candidate.evidence_refs))
        rule_confidence = int(min(3, candidate.confidence * 4))
        return {
            "rule_confidence": rule_confidence,
            "tool_corroboration": tool_corroboration,
        }

    def _llm_severity_assessment(
        self,
        candidate: VulnerabilityCandidate,
        program_slice: ProgramSlice,
        vuln_type: str,
    ) -> dict[str, str] | None:
        """Ask LLM to assess the true severity of a source_code finding.

        Hardcoded scoring tables can't distinguish "memcpy in an unreachable debug
        function" from "memcpy on attacker-controlled input in a parser entry."
        The LLM reads the actual context and provides a calibrated assessment.
        """
        if not self.llm_client:
            return None

        context_lines = (program_slice.code_excerpt or program_slice.context or "")[:1500]
        prompt = f"""你是安全审计专家。请评估以下漏洞的严重度。

漏洞类型: {vuln_type}
文件: {candidate.file_path}
行号: {candidate.line_start}
函数: {candidate.function_name or "unknown"}
Sink: {program_slice.sink}
Source: {program_slice.source}
描述: {(candidate.description or "")[:300]}

代码上下文:
```
{context_lines}
```

评估标准:
- critical: 无需认证即可远程触发，导致代码执行或系统控制
- high: 可导致代码执行、内存破坏、或权限提升，但需要一定条件
- medium: 需要特定输入或条件，可导致崩溃或信息泄露
- low: 理论风险，实际利用困难；或只是最佳实践偏离

请返回JSON: {{"severity":"critical|high|medium|low","reasoning":"简短理由"}}"""

        try:
            resp = self.llm_client.chat(
                "你是安全审计专家，只输出JSON。",
                prompt,
                timeout=25,
            )
        except Exception:
            return None

        if not resp.ok:
            return None
        text = resp.content.strip()
        try:
            result = json.loads(text)
        except json.JSONDecodeError:
            match = re.search(r"\{.*?\}", text, re.S)
            if match:
                try:
                    result = json.loads(match.group(0))
                except json.JSONDecodeError:
                    return None
            else:
                return None
        severity = str(result.get("severity", "")).lower()
        if severity not in {"critical", "high", "medium", "low"}:
            return None
        return {"severity": severity, "reasoning": str(result.get("reasoning", ""))}

    def _severity(self, total_score: int) -> str:
        if total_score >= 11:
            return "critical"
        if total_score >= 8:
            return "high"
        if total_score >= 5:
            return "medium"
        return "low"

    def _evidence_strength(self, total_score: int) -> str:
        if total_score >= 8:
            return "strong"
        if total_score >= 5:
            return "medium"
        return "weak"

    def _should_verify(self, vuln_type: VulnType, evidence_strength: str, total_score: int) -> bool:
        # Mining should not discard source-code findings before the static
        # verifier can classify the trace. Static verification later gates
        # execution to plausible / weak_static_proof findings.
        return is_dynamic_verification_candidate(vuln_type)

    def _summary(
        self,
        candidate: VulnerabilityCandidate,
        program_slice: ProgramSlice,
        total_score: int,
        score_breakdown: dict[str, int],
    ) -> str:
        return (
            f"{candidate.file_path}:{candidate.line_start} in {program_slice.function_name or 'unknown_function'} "
            f"shows {candidate.vulnerability_type}; source={program_slice.source or 'unknown'}; "
            f"sink={program_slice.sink or 'unknown'}; score={total_score}; "
            f"missing_guards={','.join(program_slice.missing_guards) or 'none'}; "
            f"tool_refs={len(program_slice.tool_run_refs)}; breakdown={score_breakdown}."
        )

    def _chain_graph(self, candidate: VulnerabilityCandidate, program_slice: ProgramSlice, vuln_type: str) -> ChainGraph:
        effect_label, effect_detail = self._effect_for(vuln_type, program_slice)
        nodes: list[ChainNode] = []
        edges: list[ChainEdge] = []
        seen_labels: set[tuple[str, str]] = set()

        def add_node(
            node_id: str,
            label: str,
            node_type: str,
            file_path: str = "",
            line: int | None = None,
            detail: str = "",
        ) -> str:
            cleaned_label = (label or "").strip()
            if not cleaned_label:
                cleaned_label = node_type
            key = (node_type, cleaned_label)
            if key in seen_labels:
                for node in nodes:
                    if node.type == node_type and node.label == cleaned_label:
                        return node.id
            seen_labels.add(key)
            safe_id = re.sub(r"[^a-zA-Z0-9_]+", "_", node_id).strip("_") or f"node_{len(nodes)}"
            if any(node.id == safe_id for node in nodes):
                safe_id = f"{safe_id}_{len(nodes)}"
            nodes.append(ChainNode(safe_id, cleaned_label, node_type, file_path, line, detail))
            return safe_id

        def connect(source: str, target: str, edge_type: str, label: str) -> None:
            if source == target:
                return
            edge_key = (source, target, edge_type, label)
            if any((edge.source, edge.target, edge.type, edge.label) == edge_key for edge in edges):
                return
            edges.append(ChainEdge(source, target, edge_type, label))

        source_label = program_slice.source or "unknown input"
        source_id = add_node("source", source_label, "source", program_slice.file_path, program_slice.line_start)
        previous_id = source_id

        call_items = [item for item in program_slice.call_chain if item]
        if program_slice.function_name and program_slice.function_name not in call_items:
            call_items.append(program_slice.function_name)
        for index, item in enumerate(call_items):
            if item == source_label or item == program_slice.sink:
                continue
            node_id = add_node(
                f"call_{index}",
                item,
                "function",
                program_slice.file_path,
                program_slice.line_start if item == program_slice.function_name else None,
                "call chain evidence",
            )
            connect(previous_id, node_id, "inferred_call", "call path")
            previous_id = node_id

        data_flow_items = [
            item
            for item in program_slice.data_flow
            if item and item not in {source_label, program_slice.sink, program_slice.function_name}
        ]
        for index, item in enumerate(data_flow_items[:6]):
            node_id = add_node(f"data_flow_{index}", item, "data_flow", detail="data-flow evidence")
            connect(previous_id, node_id, "inferred_data_flow", "data flow")
            previous_id = node_id

        if candidate.trigger_conditions:
            condition_id = add_node(
                "condition",
                "trigger condition",
                "condition",
                detail="; ".join(candidate.trigger_conditions),
            )
            connect(previous_id, condition_id, "trigger_condition", "requires")
            previous_id = condition_id

        for index, guard in enumerate(program_slice.guards[:4]):
            guard_id = add_node(f"guard_{index}", guard, "guard", program_slice.file_path, program_slice.line_start)
            connect(previous_id, guard_id, "control", "guard observed")
            previous_id = guard_id

        for index, missing_guard in enumerate(program_slice.missing_guards[:4]):
            guard_id = add_node(
                f"missing_guard_{index}",
                missing_guard,
                "missing_guard",
                program_slice.file_path,
                program_slice.line_start,
                "required control was not proven in the slice",
            )
            connect(previous_id, guard_id, "missing_control", "missing guard")
            previous_id = guard_id

        sink_id = add_node("sink", program_slice.sink or vuln_type, "sink", program_slice.file_path, program_slice.line_start)
        connect(previous_id, sink_id, "reaches", "reaches sink")
        effect_id = add_node("effect", effect_label, "effect", detail=effect_detail)
        connect(sink_id, effect_id, "triggers", "security impact")
        return ChainGraph(nodes=nodes, edges=edges)

    def _effect_for(self, vuln_type: str, program_slice: ProgramSlice) -> tuple[str, str]:
        mapping = {
            "sql_injection": ("SQL impact", "Potential unauthorized query manipulation or data exposure."),
            "command_injection": ("Command execution", "Attacker-controlled input may reach a system command."),
            "path_traversal": ("Path traversal impact", "Attacker-controlled path may escape the intended directory."),
            "unsafe_memory_copy": ("Memory corruption", "Insufficient bounds checks may enable out-of-bounds access."),
            "unsafe_c_string_api": ("Buffer overflow", "Unsafe C string API may overflow the target buffer."),
            "code_execution": ("Code execution", "Attacker-controlled data may be interpreted as executable code."),
            "deserialization": ("Deserialization impact", "Untrusted object materialization may trigger unsafe behavior."),
            "dependency_vulnerability": ("Dependency risk", "Known vulnerable dependency requires reachability confirmation."),
            "secret_leak": ("Secret exposure", "Leaked credentials may enable downstream compromise."),
            "supply_chain_config": ("Supply-chain configuration risk", "Mutable or weak CI/dependency configuration may allow unreviewed code changes."),
            "integer_overflow": ("Integer overflow", "Wraparound or truncation may bypass size checks."),
            "out_of_bounds_read": ("Out-of-bounds read", "Attacker-controlled index or offset may read beyond buffer bounds."),
            "out_of_bounds_write": ("Out-of-bounds write", "Attacker-controlled index or offset may write beyond buffer bounds."),
            "use_after_free": ("Use-after-free", "Dangling pointer dereference after memory release."),
            "double_free": ("Double free", "Freeing the same memory twice may corrupt allocator metadata."),
            "null_dereference": ("Null dereference", "Null pointer access may crash or enable further exploitation."),
            "resource_leak": ("Resource leak", "Unreleased memory/fd/handle may exhaust system resources."),
            "weak_static_proof": ("Weak static clue", "Insufficient evidence to classify as a concrete finding."),
        }
        label, detail = mapping.get(vuln_type, ("Security impact", "Security impact requires manual confirmation."))
        if program_slice.missing_guards:
            detail = f"{detail} Missing guards: {', '.join(program_slice.missing_guards)}."
        return label, detail

    def _reachability(self, program_slice: ProgramSlice) -> str:
        if program_slice.source and program_slice.call_chain:
            return "likely_reachable"
        if program_slice.source:
            return "source_identified"
        return "unknown"

    def _exploitability(self, vuln_type: str) -> str:
        if vuln_type in {"command_injection", "code_execution", "unsafe_c_string_api"}:
            return "potentially_exploitable"
        if vuln_type in {"sql_injection", "path_traversal", "unsafe_memory_copy"}:
            return "needs_runtime_confirmation"
        return "evidence_only"

    def _verification_reason(self, vuln_type: str, evidence_strength: str, total_score: int) -> str:
        vuln_type_enum = VulnType.from_string(vuln_type)
        if not is_dynamic_verification_candidate(vuln_type_enum):
            return "Static evidence should be confirmed, but dynamic verification is not prioritized."
        if evidence_strength == "strong":
            return "Source-code finding enters static gate before dynamic verification."
        return "Source-code finding is queued for static verification; dynamic execution depends on the static verdict."

    def _recommendation(self, vuln_type: str) -> str:
        mapping = {
            "sql_injection": "Use parameterized queries and constrain input types.",
            "command_injection": "Avoid shell concatenation and enforce allowlists.",
            "path_traversal": "Normalize paths and confine access to an allowlisted root.",
            "unsafe_memory_copy": "Add explicit bounds checks and use size-aware APIs.",
            "unsafe_c_string_api": "Replace unsafe C string APIs with bounded variants.",
            "code_execution": "Do not interpret untrusted data as code.",
            "deserialization": "Reject untrusted serialized objects or restrict types strictly.",
            "dependency_vulnerability": "Upgrade the affected dependency and confirm runtime reachability.",
            "secret_leak": "Rotate exposed credentials and move them to secure configuration storage.",
            "supply_chain_config": "Pin third-party actions and harden dependency automation configuration.",
            "integer_overflow": "Validate size/offset arithmetic with checked operations or safe integer types.",
            "out_of_bounds_read": "Add explicit bounds checks before array/pointer access.",
            "out_of_bounds_write": "Add explicit bounds checks and use size-aware buffer operations.",
            "use_after_free": "Set pointers to NULL after free and review object lifetime management.",
            "double_free": "Ensure each allocation is freed exactly once with clear ownership semantics.",
            "null_dereference": "Add null checks before pointer dereference.",
            "resource_leak": "Ensure every allocation/open has a corresponding release/close path.",
            "weak_static_proof": "Gather additional static or dynamic evidence before concluding.",
        }
        return mapping.get(vuln_type, "Add validation, bounds checks, and focused regression tests.")

    def _payloads_for(self, vuln_type: str) -> list[str]:
        mapping = {
            "sql_injection": ["' OR '1'='1", "1 UNION SELECT NULL"],
            "command_injection": ["127.0.0.1; id", "$(id)"],
            "path_traversal": ["../../../../etc/passwd", "..\\..\\..\\Windows\\win.ini"],
            "unsafe_memory_copy": ["A" * 4096],
            "unsafe_c_string_api": ["A" * 4096],
            "integer_overflow": ["2147483647", "-2147483648"],
            "out_of_bounds_read": ["A" * 4096],
            "out_of_bounds_write": ["A" * 4096],
            "use_after_free": [],
            "double_free": [],
            "null_dereference": [],
            "resource_leak": [],
            "code_execution": ["__import__('os').system('id')"],
        }
        return mapping.get(vuln_type, [])


class VulnerabilityMiningAgent:
    """Agent that owns the full vulnerability mining workflow."""

    def __init__(
        self,
        tool_runner: SecurityToolRunner | ToolRunner,
        llm_client: DeepSeekClient,
        event_sink: Callable[[str, str, str, dict[str, Any]], None] | None = None,
        tool_planner: ToolPlanner | None = None,
        mining_director: Any | None = None,
    ) -> None:
        if isinstance(tool_runner, SecurityToolRunner):
            self.tool_runner = tool_runner.tool_runner
            self.tool_planner = tool_runner.planner
        else:
            self.tool_runner = tool_runner
            self.tool_planner = tool_planner or ToolPlanner(
                self.tool_runner.registry,
                self.tool_runner.env,
                availability_provider=self.tool_runner.list_tools,
            )
        self.llm_client = llm_client
        self.event_sink = event_sink
        self.locator = DangerousFunctionLocator()
        self.slice_analyzer = SliceAnalyzer()
        self.candidate_generator = CandidateGenerator(llm_client=llm_client)
        self.aggregator = ClueAggregator()
        self.classifier = VulnerabilityClassifier(llm_client=llm_client)
        # MiningDirector is optional; instantiate one if not injected
        if mining_director:
            self.mining_director = mining_director
        else:
            from .mining_director import MiningDirector as MD
            self.mining_director = MD(llm_client)

    def run(
        self, target: Path, profile: ProjectProfile, semantic_index: SemanticIndex,
        strategy: MiningStrategy | None = None,
        mode: str = "standard",
    ) -> MiningResult:
        result = MiningResult()
        budget = AuditBudget.for_mode(mode)
        usage = BudgetUsage(config_audit_enabled=budget.enable_config_audit)
        result.budget = budget.to_dict()
        result.events.append(self._event("mine_vulnerabilities", "running", "mining started"))

        # --- tool selection: merge planner recommendations with MiningDirector strategy ---
        recommendations = self.tool_planner.recommend_tools(
            "VulnerabilityMiningAgent",
            "mine_vulnerabilities",
            profile,
            target,
        )
        planner_tool_order = [item.name for item in recommendations]
        # Strategy-recommended tools override or augment the planner list
        if strategy and strategy.tool_selections:
            strategy_tool_names = {ts.name for ts in strategy.tool_selections}
            # Prepend strategy tools that the planner didn't already recommend
            extra_recs = [rec for rec in recommendations if rec.name not in strategy_tool_names]
            # Build a merged list: strategy tools first (sorted by priority), then planner extras
            merged: list[Any] = []
            for ts in sorted(strategy.tool_selections, key=lambda x: x.priority):
                matching = [r for r in recommendations if r.name == ts.name]
                if matching:
                    merged.append(matching[0])
            merged.extend(extra_recs)
            recommendations = merged
            self._emit_step_start("tooling", f"strategy merged: {len(strategy.tool_selections)} director tools + {len(extra_recs)} planner extras", {})
        final_tool_order = [item.name for item in recommendations]

        self._emit_step_start("tooling", "security tools selected", {"project_type": profile.project_type})
        invocations = self.tool_planner.build_invocations(recommendations, target)
        result.tool_results = run_invocations_parallel(invocations, self.tool_runner)
        self._emit_step_done(
            "tooling",
            "security tools completed",
            {"tools": [f"{item.tool}:{item.status}" for item in result.tool_results]},
        )

        self._emit_step_start("dangerous_function_location", "locating dangerous anchors", {})
        result.dangerous_functions = self.locator.locate(target, result.tool_results, budget, strategy)
        usage.anchors = len(result.dangerous_functions)
        usage.anchors_before_budget = usage.anchors + sum(self.locator.last_suppressed_counts.values())
        usage.config_anchors_suppressed = self.locator.last_suppressed_counts.get("config", 0)
        usage.weak_signal_anchors_suppressed = self.locator.last_suppressed_counts.get("weak_signal", 0)
        self._emit_step_done(
            "dangerous_function_location",
            "anchors located",
            {
                "dangerous_functions": len(result.dangerous_functions),
                "budget": budget.to_dict(),
                "suppressed": self.locator.last_suppressed_counts,
            },
        )

        self._emit_step_start("slicing", "building structured slices", {"dangerous_functions": len(result.dangerous_functions)})
        result.program_slices = self.slice_analyzer.analyze(
            target, result.dangerous_functions, semantic_index, self.llm_client, budget, strategy
        )
        usage.slices = len(result.program_slices)
        self._emit_step_done("slicing", "structured slices ready", {"program_slices": len(result.program_slices)})

        self._emit_step_start("candidate_generation", "generating candidates in batches", {"program_slices": len(result.program_slices)})
        result.candidates = self.candidate_generator.generate(result.program_slices, self.llm_client, budget)
        usage.candidates = len(result.candidates)
        usage.llm_calls = self.candidate_generator.llm_calls_used
        self._emit_step_done(
            "candidate_generation",
            "candidates generated",
            {"candidates": len(result.candidates), "llm_calls": usage.llm_calls},
        )

        self._emit_step_start("clue_aggregation", "merging candidate clues", {"candidates": len(result.candidates)})
        result.aggregated_candidates = self.aggregator.aggregate(result.candidates)
        usage.aggregated_candidates = len(result.aggregated_candidates)
        self._emit_step_done("clue_aggregation", "candidate clues merged", {"aggregated_candidates": len(result.aggregated_candidates)})

        # --- apply MiningDirector candidate prioritisation ---
        candidate_top_before = [item.id for item in result.aggregated_candidates[:10]]
        if strategy and result.aggregated_candidates:
            result.aggregated_candidates = self.mining_director.prioritize_candidates(
                result.aggregated_candidates, strategy, profile
            )
            self._emit_step_start("mining_director_prioritize", "candidates reordered by strategy", {"count": len(result.aggregated_candidates)})
        candidate_top_after = [item.id for item in result.aggregated_candidates[:10]]

        self._emit_step_start("vulnerability_classification", "classifying findings", {"candidates": len(result.aggregated_candidates)})
        result.findings = self.classifier.classify(result.aggregated_candidates, result.program_slices, self.llm_client, budget)
        usage.findings = len(result.findings)
        result.budget_usage = usage.to_dict()
        result.strategy_effects = {
            "planner_tool_order": planner_tool_order,
            "final_tool_order": final_tool_order,
            "anchor_top_ids": [item.id for item in result.dangerous_functions[:10]],
            "slice_top_ids": [item.id for item in result.program_slices[:10]],
            "candidate_top_before": candidate_top_before,
            "candidate_top_after": candidate_top_after,
            "verification_queue_top_ids": [item.id for item in result.findings if item.should_verify][:10],
        }
        self._emit_step_done("vulnerability_classification", "findings classified", {"findings": len(result.findings)})

        # Save strategy for debug output
        if strategy:
            strategy.strategy_effects = result.strategy_effects
            result.strategy = strategy.to_dict()

        result.events.append(
            self._event(
                "mine_vulnerabilities",
                "completed",
                (
                    f"tools={len(result.tool_results)}; dangerous_functions={len(result.dangerous_functions)}; "
                    f"slices={len(result.program_slices)}; candidates={len(result.candidates)}; findings={len(result.findings)}"
                ),
            )
        )
        return result

    def _event(self, action: str, status: str, detail: str) -> AgentEvent:
        event = AgentEvent(agent="VulnerabilityMiningAgent", action=action, status=status, detail=detail)
        if status in {"completed", "failed"}:
            event.finished_at = utc_now()
        return event

    def _emit_step_start(self, step: str, message: str, metadata: dict[str, Any]) -> None:
        self._emit("mining_step_start", message, {"step": step, **metadata})

    def _emit_step_done(self, step: str, message: str, metadata: dict[str, Any]) -> None:
        self._emit("mining_step_done", message, {"step": step, **metadata})

    def _emit(self, event_type: str, message: str, metadata: dict[str, Any]) -> None:
        if self.event_sink:
            self.event_sink("VulnerabilityMiningAgent", event_type, message, metadata)
