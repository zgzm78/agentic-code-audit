from __future__ import annotations

import ast
import hashlib
import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..llm import DeepSeekClient
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
from ..tools.runner import SecurityToolRunner, ToolPlanner, ToolRunner


@dataclass
class MiningResult:
    tool_results: list[ToolResult] = field(default_factory=list)
    dangerous_functions: list[DangerousFunction] = field(default_factory=list)
    program_slices: list[ProgramSlice] = field(default_factory=list)
    candidates: list[VulnerabilityCandidate] = field(default_factory=list)
    aggregated_candidates: list[VulnerabilityCandidate] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    events: list[AgentEvent] = field(default_factory=list)


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

    def locate(self, target: Path, tool_results: list[ToolResult]) -> list[DangerousFunction]:
        rules = self.rules_loader.load()
        boundary_hints = self._boundary_hints(target)
        skipped_optional = [item.tool for item in tool_results if item.status == "skipped"]
        anchors = self._from_rules(target, rules, boundary_hints, skipped_optional)
        anchors.extend(self._from_tools(target, tool_results))
        return self._merge(anchors)

    def _from_rules(
        self,
        target: Path,
        rules: dict[str, Any],
        boundary_hints: dict[str, list[dict[str, Any]]],
        skipped_optional: list[str],
    ) -> list[DangerousFunction]:
        anchors: list[DangerousFunction] = []
        grouped_rules = {
            ".py": list(rules.get("python.dangerous_apis", {}).get("rules") or []),
            ".js": list(rules.get("javascript.dangerous_apis", {}).get("rules") or []),
            ".jsx": list(rules.get("javascript.dangerous_apis", {}).get("rules") or []),
            ".ts": list(rules.get("javascript.dangerous_apis", {}).get("rules") or []),
            ".tsx": list(rules.get("javascript.dangerous_apis", {}).get("rules") or []),
            ".c": list(rules.get("cpp.dangerous_functions", {}).get("rules") or []),
            ".cc": list(rules.get("cpp.dangerous_functions", {}).get("rules") or []),
            ".cpp": list(rules.get("cpp.dangerous_functions", {}).get("rules") or []),
            ".cxx": list(rules.get("cpp.dangerous_functions", {}).get("rules") or []),
            ".h": list(rules.get("cpp.dangerous_functions", {}).get("rules") or []),
            ".hpp": list(rules.get("cpp.dangerous_functions", {}).get("rules") or []),
        }
        common_rules = [
            {"pattern": pattern, "api": api, "vuln_type": vuln_type, "category": category, "confidence": confidence}
            for pattern, api, vuln_type, category, confidence in self.COMMON_PATTERNS
        ]
        for path in target.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in self.SUFFIX_LANGUAGE or ".git" in path.parts:
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
                        )
                    )
        return anchors

    def _from_tools(self, target: Path, tool_results: list[ToolResult]) -> list[DangerousFunction]:
        anchors: list[DangerousFunction] = []
        for result in tool_results:
            if result.tool == "semgrep" and isinstance(result.raw, dict):
                anchors.extend(self._semgrep_anchors(result))
            elif result.tool == "bandit" and isinstance(result.raw, dict):
                anchors.extend(self._bandit_anchors(result))
            elif result.tool == "cppcheck":
                anchors.extend(self._cppcheck_anchors(target, result))
            elif result.tool == "gosec" and isinstance(result.raw, dict):
                anchors.extend(self._gosec_anchors(target, result))
            elif result.tool in {"npm-audit", "pip-audit", "cargo-audit", "osv-scanner"}:
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

    def _cppcheck_anchors(self, target: Path, result: ToolResult) -> list[DangerousFunction]:
        anchors: list[DangerousFunction] = []
        artifact_refs = self._artifact_refs(result)
        for item in result.findings:
            file_path = self._relative_tool_path(target, str(item.get("location_file") or item.get("file") or ""))
            line = self._int(item.get("location_line") or item.get("line"), 1)
            rule_id = str(item.get("id") or "cppcheck")
            anchors.append(
                DangerousFunction(
                    id=self._id(file_path, line, rule_id),
                    file_path=file_path,
                    line_start=line,
                    function_name="",
                    dangerous_api=rule_id,
                    category="tool",
                    snippet=str(item.get("msg") or item.get("verbose") or "")[:500],
                    language="C/C++",
                    kind="tool_finding",
                    rule_id=rule_id,
                    confidence=0.6,
                    sink=rule_id,
                    evidence=[str(item.get("msg") or "cppcheck finding")],
                    tool_run_refs=[result.run_id],
                    artifact_refs=artifact_refs,
                    tool="cppcheck",
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
                proc = subprocess.run(
                    [ctags, "-x", "--c-kinds=f", str(path)],
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    capture_output=True,
                    timeout=10,
                    check=False,
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

    SOURCE_PATTERNS = [
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
    SANITIZER_PATTERNS = [
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
    ) -> list[ProgramSlice]:
        slices: list[ProgramSlice] = []
        for anchor in dangerous_functions[:160]:
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
            guards = [text.strip() for _, text in context_lines if re.search(r"\b(if|while|for|switch|case|assert)\b", text)]
            sanitizers = [text.strip() for _, text in context_lines if self._has_any(text, self.SANITIZER_PATTERNS)]
            definitions = [text.strip() for _, text in context_lines if re.search(r"\b\w+\s*=\s*.+", text)]
            sink_line = lines[anchor.line_start - 1] if 1 <= anchor.line_start <= len(lines) else anchor.snippet
            sink_args = self._extract_args(sink_line)
            parameters = self._infer_parameters(lines, start, end)
            missing_guards = self._missing_guards(anchor, source, guards, sanitizers)
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
                )
            )
        return slices

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
        ctags = shutil.which("ctags")
        if ctags:
            try:
                proc = subprocess.run(
                    [ctags, "-x", "--c-kinds=f", str(path)],
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    capture_output=True,
                    timeout=10,
                    check=False,
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


class CandidateGenerator:
    def __init__(self, cwe_mapping: dict[str, str] | None = None) -> None:
        self.cwe_mapping = cwe_mapping or dict(RulesLoader().load().get("common.cwe_mapping") or {})

    def generate(self, slices: list[ProgramSlice], llm_client: DeepSeekClient) -> list[VulnerabilityCandidate]:
        candidates: list[VulnerabilityCandidate] = []
        grouped: dict[tuple[str, str], list[ProgramSlice]] = {}
        for program_slice in slices[:120]:
            inferred = self._type_from_sink(program_slice.sink)
            grouped.setdefault((self._language(program_slice.file_path), inferred), []).append(program_slice)
        for (_language, _vuln_type), group in grouped.items():
            batch_size = max(3, min(4, 8))
            for index in range(0, len(group), batch_size):
                batch = group[index : index + batch_size]
                llm_candidates = self._ask_llm_batch(batch, llm_client)
                for slice_index, program_slice in enumerate(batch):
                    raw = llm_candidates[slice_index] if slice_index < len(llm_candidates) else None
                    candidate = self._candidate_from_raw(program_slice, raw) if raw else self._fallback_candidate(program_slice)
                    candidates.append(candidate)
        return candidates

    def _ask_llm_batch(self, slices: list[ProgramSlice], llm_client: DeepSeekClient) -> list[dict[str, Any]]:
        if not hasattr(llm_client, "chat"):
            return []
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
        vuln_type = str(raw.get("vulnerability_type") or self._type_from_sink(program_slice.sink))
        trigger_conditions = [str(item) for item in raw.get("trigger_conditions") or raw.get("trigger_condition") or []]
        if isinstance(raw.get("trigger_condition"), str):
            trigger_conditions = [str(raw["trigger_condition"])]
        valid, validity = self._validate_candidate(program_slice, trigger_conditions)
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
            evidence=[str(item) for item in raw.get("evidence", [])][:12],
            cwe=self.cwe_mapping.get(vuln_type, ""),
            sink=program_slice.sink,
            source=program_slice.source,
            missing_checks=[str(item) for item in raw.get("missing_checks", [])][:8],
            assumptions=[str(item) for item in raw.get("assumptions", [])][:8],
            evidence_refs=[program_slice.id, *program_slice.tool_run_refs, *program_slice.artifact_refs],
            confidence=self._parse_confidence(raw.get("confidence")),
            valid=valid,
            validity=validity,
            llm_reasoning=str(raw.get("llm_reasoning") or ""),
        )

    def _fallback_candidate(self, program_slice: ProgramSlice) -> VulnerabilityCandidate:
        vuln_type = self._type_from_sink(program_slice.sink)
        trigger_conditions = [program_slice.source] if program_slice.source else []
        valid, validity = self._validate_candidate(program_slice, trigger_conditions)
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
            assumptions=["fallback_candidate"],
            evidence_refs=[program_slice.id, *program_slice.tool_run_refs, *program_slice.artifact_refs],
            confidence=0.48,
            valid=valid,
            validity=validity,
            llm_reasoning=program_slice.llm_summary,
        )

    def _validate_candidate(self, program_slice: ProgramSlice, trigger_conditions: list[str]) -> tuple[bool, str]:
        static_sources = {"dependency manifest", "source literal", "configuration file", "static evidence"}
        has_required_context = bool(program_slice.function_name) or program_slice.source in static_sources
        required = all(
            [
                bool(program_slice.file_path),
                bool(program_slice.line_start),
                bool(program_slice.sink),
                has_required_context,
                bool(trigger_conditions),
            ]
        )
        return (required, "valid" if required else "invalid_candidate")

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
        value = sink.lower()
        if "strcpy" in value or "strcat" in value or "sprintf" in value or "gets" in value:
            return "unsafe_c_string_api"
        if "memcpy" in value:
            return "unsafe_memory_copy"
        if "system" in value or "popen" in value or "subprocess" in value or "child_process" in value:
            return "command_injection"
        if "execute" in value or "sql" in value:
            return "sql_injection"
        if "open" in value or "send_file" in value:
            return "path_traversal"
        if "eval" in value:
            return "code_execution"
        if "pickle" in value or "yaml.load" in value:
            return "deserialization"
        if "cve" in value or "ghsa" in value or "rustsec" in value or "pysec" in value:
            return "dependency_vulnerability"
        if "gitleaks" in value or "secret" in value:
            return "secret_leak"
        if any(token in value for token in ("github-actions", "dependabot", "mutable-action", "workflow", "supply-chain")):
            return "supply_chain_config"
        return "other"

    def _severity_for(self, vuln_type: str) -> str:
        if vuln_type in {"command_injection", "code_execution", "unsafe_c_string_api", "unsafe_memory_copy"}:
            return "high"
        if vuln_type in {"sql_injection", "deserialization"}:
            return "medium"
        if vuln_type == "supply_chain_config":
            return "medium"
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


class ClueAggregator:
    def aggregate(self, candidates: list[VulnerabilityCandidate]) -> list[VulnerabilityCandidate]:
        merged: dict[tuple[str, str, str, str], VulnerabilityCandidate] = {}
        trigger_counts: dict[tuple[str, str, str, str], int] = {}
        for candidate in candidates:
            if not candidate.valid or candidate.validity != "valid":
                continue
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
        if candidate.confidence >= 0.75 or len(candidate.evidence) >= 4:
            return "strong"
        if candidate.confidence >= 0.55 or len(candidate.evidence) >= 2:
            return "medium"
        return "weak"


class VulnerabilityClassifier:
    TAXONOMY = {
        "sql_injection": ("CWE-89", "A03:2021-Injection"),
        "command_injection": ("CWE-78", "A03:2021-Injection"),
        "path_traversal": ("CWE-22", "A01:2021-Broken Access Control"),
        "unsafe_memory_copy": ("CWE-787", "Memory Safety"),
        "unsafe_c_string_api": ("CWE-120", "Memory Safety"),
        "code_execution": ("CWE-94", "A03:2021-Injection"),
        "deserialization": ("CWE-502", "A08:2021-Software and Data Integrity Failures"),
        "dependency_vulnerability": ("CWE-1104", "Vulnerable and Outdated Components"),
        "secret_leak": ("CWE-798", "A07:2021-Identification and Authentication Failures"),
        "supply_chain_config": ("CWE-829", "A08:2021-Software and Data Integrity Failures"),
    }

    def classify(
        self,
        candidates: list[VulnerabilityCandidate],
        slices: list[ProgramSlice],
        llm_client: DeepSeekClient,
    ) -> list[Finding]:
        slices_by_id = {item.id: item for item in slices}
        findings: list[Finding] = []
        for candidate in candidates[:80]:
            program_slice = slices_by_id.get(candidate.slice_id)
            if not program_slice:
                continue
            vuln_type = candidate.vulnerability_type
            cwe, owasp = self.TAXONOMY.get(vuln_type, ("", ""))
            score_breakdown = self._score(vuln_type, candidate, program_slice)
            total_score = sum(score_breakdown.values())
            severity = self._severity(total_score)
            evidence_strength = self._evidence_strength(total_score)
            should_verify = self._should_verify(vuln_type, evidence_strength, total_score)
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
                    evidence=[*candidate.evidence, summary, f"score={total_score}", *[f"{k}={v}" for k, v in score_breakdown.items()]],
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
                )
            )
        return findings

    def _score(self, vuln_type: str, candidate: VulnerabilityCandidate, program_slice: ProgramSlice) -> dict[str, int]:
        sink_danger = {
            "command_injection": 3,
            "code_execution": 3,
            "unsafe_c_string_api": 3,
            "unsafe_memory_copy": 3,
            "sql_injection": 2,
            "path_traversal": 2,
            "deserialization": 2,
            "dependency_vulnerability": 1,
            "secret_leak": 1,
            "supply_chain_config": 1,
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

    def _should_verify(self, vuln_type: str, evidence_strength: str, total_score: int) -> bool:
        if vuln_type in {"dependency_vulnerability", "secret_leak", "supply_chain_config"}:
            return False
        if evidence_strength == "strong":
            return True
        return total_score >= 6

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
        nodes = [
            ChainNode("source", program_slice.source or "unknown input", "source", program_slice.file_path, program_slice.line_start),
            ChainNode("function", program_slice.function_name or program_slice.file_path, "function", program_slice.file_path, program_slice.line_start),
            ChainNode("condition", "trigger condition", "condition", detail="; ".join(candidate.trigger_conditions) or "reachability inferred from slice"),
            ChainNode("sink", program_slice.sink or vuln_type, "sink", program_slice.file_path, program_slice.line_start),
            ChainNode("effect", effect_label, "effect", detail=effect_detail),
        ]
        edges = [
            ChainEdge("source", "function", "passes_data", "input reaches function"),
            ChainEdge("function", "condition", "guards", "function-level controls"),
            ChainEdge("condition", "sink", "reaches", "trigger path reaches sink"),
            ChainEdge("sink", "effect", "triggers", "security impact"),
        ]
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
        if vuln_type in {"dependency_vulnerability", "secret_leak", "supply_chain_config"}:
            return "Static evidence should be confirmed, but dynamic verification is not prioritized."
        if evidence_strength == "strong":
            return "Strong source-to-sink evidence justifies verification."
        if total_score >= 6:
            return "Rule score crosses the verification threshold."
        return "Evidence is currently too weak for prioritized verification."

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
        }
        return mapping.get(vuln_type, "Add validation, bounds checks, and focused regression tests.")

    def _payloads_for(self, vuln_type: str) -> list[str]:
        mapping = {
            "sql_injection": ["' OR '1'='1", "1 UNION SELECT NULL"],
            "command_injection": ["127.0.0.1; id", "$(id)"],
            "path_traversal": ["../../../../etc/passwd", "..\\..\\..\\Windows\\win.ini"],
            "unsafe_memory_copy": ["A" * 4096],
            "unsafe_c_string_api": ["A" * 4096],
            "code_execution": ["__import__('os').system('id')"],
        }
        return mapping.get(vuln_type, ["manual-validation-payload"])


class VulnerabilityMiningAgent:
    """Agent that owns the full vulnerability mining workflow."""

    def __init__(
        self,
        tool_runner: SecurityToolRunner | ToolRunner,
        llm_client: DeepSeekClient,
        event_sink: Callable[[str, str, str, dict[str, Any]], None] | None = None,
        tool_planner: ToolPlanner | None = None,
    ) -> None:
        if isinstance(tool_runner, SecurityToolRunner):
            self.tool_runner = tool_runner.tool_runner
            self.tool_planner = tool_runner.planner
        else:
            self.tool_runner = tool_runner
            self.tool_planner = tool_planner or ToolPlanner(self.tool_runner.registry, self.tool_runner.env)
        self.llm_client = llm_client
        self.event_sink = event_sink
        self.locator = DangerousFunctionLocator()
        self.slice_analyzer = SliceAnalyzer()
        self.candidate_generator = CandidateGenerator()
        self.aggregator = ClueAggregator()
        self.classifier = VulnerabilityClassifier()

    def run(self, target: Path, profile: ProjectProfile, semantic_index: SemanticIndex) -> MiningResult:
        result = MiningResult()
        result.events.append(self._event("mine_vulnerabilities", "running", "mining started"))

        recommendations = self.tool_planner.recommend_tools(
            "VulnerabilityMiningAgent",
            "mine_vulnerabilities",
            profile,
            target,
        )
        self._emit_step_start("tooling", "security tools selected", {"project_type": profile.project_type})
        for invocation in self.tool_planner.build_invocations(recommendations, target):
            result.tool_results.append(self.tool_runner.run(invocation))
        self._emit_step_done(
            "tooling",
            "security tools completed",
            {"tools": [f"{item.tool}:{item.status}" for item in result.tool_results]},
        )

        self._emit_step_start("dangerous_function_location", "locating dangerous anchors", {})
        result.dangerous_functions = self.locator.locate(target, result.tool_results)
        self._emit_step_done("dangerous_function_location", "anchors located", {"dangerous_functions": len(result.dangerous_functions)})

        self._emit_step_start("slicing", "building structured slices", {"dangerous_functions": len(result.dangerous_functions)})
        result.program_slices = self.slice_analyzer.analyze(target, result.dangerous_functions, semantic_index, self.llm_client)
        self._emit_step_done("slicing", "structured slices ready", {"program_slices": len(result.program_slices)})

        self._emit_step_start("candidate_generation", "generating candidates in batches", {"program_slices": len(result.program_slices)})
        result.candidates = self.candidate_generator.generate(result.program_slices, self.llm_client)
        self._emit_step_done("candidate_generation", "candidates generated", {"candidates": len(result.candidates)})

        self._emit_step_start("clue_aggregation", "merging candidate clues", {"candidates": len(result.candidates)})
        result.aggregated_candidates = self.aggregator.aggregate(result.candidates)
        self._emit_step_done("clue_aggregation", "candidate clues merged", {"aggregated_candidates": len(result.aggregated_candidates)})

        self._emit_step_start("vulnerability_classification", "classifying findings", {"candidates": len(result.aggregated_candidates)})
        result.findings = self.classifier.classify(result.aggregated_candidates, result.program_slices, self.llm_client)
        self._emit_step_done("vulnerability_classification", "findings classified", {"findings": len(result.findings)})

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
