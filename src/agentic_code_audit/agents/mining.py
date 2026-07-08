from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from ..llm import DeepSeekClient
from ..models import (
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
)


class DangerousFunctionLocator:
    """Locate dangerous APIs, risky functions and tool-provided anchors."""

    PATTERNS: list[tuple[str, str, str, str]] = [
        (r"\bstrcpy\s*\(", "unsafe_c_string_api", "strcpy", "memory"),
        (r"\bstrcat\s*\(", "unsafe_c_string_api", "strcat", "memory"),
        (r"\bsprintf\s*\(", "unsafe_c_string_api", "sprintf", "memory"),
        (r"\bmemcpy\s*\(", "unsafe_memory_copy", "memcpy", "memory"),
        (r"\bsystem\s*\(", "command_injection", "system", "command"),
        (r"\bpopen\s*\(", "command_injection", "popen", "command"),
        (r"subprocess\.(run|Popen|call|check_output)", "command_injection", "subprocess", "command"),
        (r"os\.system\s*\(", "command_injection", "os.system", "command"),
        (r"execute\s*\(.*(%|\+|format|f[\"'])", "sql_injection", "execute", "sql"),
        (r"SELECT\s+.*\+", "sql_injection", "sql_concat", "sql"),
        (r"open\s*\(.*request\.", "path_traversal", "open", "file"),
        (r"send_file\s*\(", "path_traversal", "send_file", "file"),
        (r"child_process\.(exec|spawn|execSync)", "command_injection", "child_process", "command"),
        (r"eval\s*\(", "code_execution", "eval", "code"),
        (r"pickle\.loads\s*\(", "deserialization", "pickle.loads", "deserialization"),
        (r"yaml\.load\s*\(", "deserialization", "yaml.load", "deserialization"),
    ]

    SUFFIXES = {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".c",
        ".cc",
        ".cpp",
        ".cxx",
        ".h",
        ".hpp",
        ".php",
        ".java",
        ".go",
        ".rs",
    }

    def locate(self, target: Path, tool_results: list[ToolResult]) -> list[DangerousFunction]:
        anchors = self._from_source(target)
        anchors.extend(self._from_tools(tool_results))
        return self._dedupe(anchors)

    def _from_source(self, target: Path) -> list[DangerousFunction]:
        anchors: list[DangerousFunction] = []
        for path in target.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in self.SUFFIXES or ".git" in path.parts:
                continue
            try:
                lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            rel = normalize_path(path, target)
            for index, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith(("#", "//", "*")):
                    continue
                for pattern, vuln_type, api, category in self.PATTERNS:
                    if re.search(pattern, line, flags=re.IGNORECASE):
                        function_name = self._nearest_function(lines, index)
                        anchors.append(
                            DangerousFunction(
                                id=self._id(rel, index, api),
                                file_path=rel,
                                line_start=index,
                                function_name=function_name,
                                dangerous_api=api,
                                category=category,
                                snippet=stripped[:500],
                                sink=api,
                                evidence=[f"危险 API 规则匹配: {api}", f"推断漏洞类型: {vuln_type}"],
                            )
                        )
        return anchors

    def _from_tools(self, tool_results: list[ToolResult]) -> list[DangerousFunction]:
        anchors: list[DangerousFunction] = []
        for result in tool_results:
            if result.tool == "semgrep" and isinstance(result.raw, dict):
                for item in result.raw.get("results", []):
                    path = item.get("path", "")
                    line = item.get("start", {}).get("line") or 1
                    check_id = item.get("check_id", "semgrep")
                    extra = item.get("extra", {})
                    anchors.append(
                        DangerousFunction(
                            id=self._id(path, line, check_id),
                            file_path=path,
                            line_start=line,
                            function_name="",
                            dangerous_api=check_id,
                            category="tool",
                            snippet=(extra.get("lines") or "").strip()[:500],
                            evidence=[f"Semgrep: {check_id}", extra.get("message", "")],
                            tool="semgrep",
                        )
                    )
            if result.tool == "bandit" and isinstance(result.raw, dict):
                for item in result.raw.get("results", []):
                    path = item.get("filename", "")
                    line = item.get("line_number") or 1
                    test_id = item.get("test_id", "bandit")
                    anchors.append(
                        DangerousFunction(
                            id=self._id(path, line, test_id),
                            file_path=path,
                            line_start=line,
                            function_name="",
                            dangerous_api=test_id,
                            category="tool",
                            snippet=(item.get("code") or "").strip()[:500],
                            evidence=[f"Bandit: {test_id}", item.get("issue_text", "")],
                            tool="bandit",
                        )
                    )
        return anchors

    def _nearest_function(self, lines: list[str], line_number: int) -> str:
        for index in range(line_number - 1, max(-1, line_number - 80), -1):
            line = lines[index].strip()
            match = re.search(r"\bdef\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", line)
            if match:
                return match.group(1).strip()
            match = re.search(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", line)
            if match:
                return match.group(1).strip()

            if re.match(r"^(return|if|for|while|switch|catch|else)\b", line):
                continue
            if ";" in line:
                continue
            next_line = lines[index + 1].strip() if index + 1 < len(lines) else ""
            if "{" not in line and next_line != "{":
                continue
            match = re.search(
                r"(?:[\w:<>\*&]+\s+)+([A-Za-z_~][A-Za-z0-9_:~]*)\s*\([^;{}]*\)\s*(?:\{|$)",
                line,
            )
            if match:
                return match.group(1).split("::")[-1].strip()
        return ""

    def _dedupe(self, anchors: list[DangerousFunction]) -> list[DangerousFunction]:
        seen: set[tuple[str, int, str]] = set()
        output: list[DangerousFunction] = []
        for anchor in anchors:
            key = (anchor.file_path, anchor.line_start, anchor.dangerous_api)
            if key in seen:
                continue
            seen.add(key)
            output.append(anchor)
        return output

    def _id(self, path: str, line: int, api: str) -> str:
        return hashlib.sha1(f"{path}:{line}:{api}".encode("utf-8")).hexdigest()[:12]


class SliceAnalyzer:
    """Build a lightweight backward/forward slice around each dangerous anchor."""

    SOURCE_PATTERNS = [
        r"request\.(args|form|json|values|GET|POST)",
        r"req\.(query|body|params)",
        r"\$_(GET|POST|REQUEST)",
        r"argv|argc",
        r"stdin|input\s*\(",
        r"read\s*\(",
        r"fread\s*\(",
    ]

    def analyze(
        self,
        target: Path,
        dangerous_functions: list[DangerousFunction],
        semantic_index: SemanticIndex,
        llm_client: DeepSeekClient,
    ) -> list[ProgramSlice]:
        slices: list[ProgramSlice] = []
        for anchor in dangerous_functions[:120]:
            path = target / anchor.file_path
            try:
                lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            start = max(1, anchor.line_start - 20)
            end = min(len(lines), anchor.line_start + 20)
            context_lines = [(idx, lines[idx - 1]) for idx in range(start, end + 1)]
            context = "\n".join(f"{idx}: {text}" for idx, text in context_lines)
            source = self._infer_source(context)
            controls = [text.strip() for _, text in context_lines if re.search(r"\b(if|while|for|switch)\b", text)]
            params = self._infer_parameters(lines, anchor.line_start)
            call_chain = self._call_chain(anchor, semantic_index)
            data_flow = [source or "未知输入来源", anchor.function_name or anchor.file_path, anchor.sink or anchor.dangerous_api]
            llm_summary = self._summarize_with_llm(anchor, context, llm_client)
            slices.append(
                ProgramSlice(
                    id=self._id(anchor.id, context),
                    dangerous_function_id=anchor.id,
                    file_path=anchor.file_path,
                    line_start=anchor.line_start,
                    function_name=anchor.function_name,
                    source=source,
                    sink=anchor.sink or anchor.dangerous_api,
                    controls=controls[:8],
                    parameters=params,
                    call_chain=call_chain,
                    data_flow=data_flow,
                    context=context,
                    llm_summary=llm_summary,
                )
            )
        return slices

    def _infer_source(self, context: str) -> str:
        for pattern in self.SOURCE_PATTERNS:
            match = re.search(pattern, context, flags=re.IGNORECASE)
            if match:
                return match.group(0)
        return ""

    def _infer_parameters(self, lines: list[str], line_number: int) -> list[str]:
        for index in range(line_number - 1, max(-1, line_number - 80), -1):
            match = re.search(r"\(([^)]*)\)", lines[index])
            if match and ("def " in lines[index] or "function " in lines[index] or "{" in lines[index]):
                return [part.strip() for part in match.group(1).split(",") if part.strip()][:12]
        return []

    def _call_chain(self, anchor: DangerousFunction, semantic_index: SemanticIndex) -> list[str]:
        chain = [anchor.function_name or anchor.file_path, anchor.dangerous_api]
        for route in semantic_index.routes:
            if route.file_path == anchor.file_path and route.line_start <= anchor.line_start:
                return [f"{route.method} {route.route}", route.handler, *chain]
        return chain

    def _summarize_with_llm(self, anchor: DangerousFunction, context: str, llm_client: DeepSeekClient) -> str:
        prompt = "你是源码安全审计智能体。请用中文解释危险函数附近的数据流、边界检查和可能触发条件。"
        user = json.dumps(
            {
                "dangerous_function": anchor.__dict__,
                "context": context[:6000],
                "output": "返回 3-6 句中文，必须说明输入来源、危险函数、缺失检查和可能影响。",
            },
            ensure_ascii=False,
        )
        response = llm_client.chat(prompt, user, timeout=90)
        if response.ok:
            return response.content.strip()[:2000]
        return f"LLM 切片解释失败: {response.error}"

    def _id(self, anchor_id: str, context: str) -> str:
        return hashlib.sha1(f"{anchor_id}:{context[:200]}".encode("utf-8")).hexdigest()[:12]


class CandidateGenerator:
    def generate(self, slices: list[ProgramSlice], llm_client: DeepSeekClient) -> list[VulnerabilityCandidate]:
        candidates: list[VulnerabilityCandidate] = []
        for program_slice in slices[:80]:
            llm_candidate = self._ask_llm(program_slice, llm_client)
            candidates.append(llm_candidate or self._fallback_candidate(program_slice))
        return candidates

    def _ask_llm(self, program_slice: ProgramSlice, llm_client: DeepSeekClient) -> VulnerabilityCandidate | None:
        prompt = (
            "你是漏洞候选生成智能体。基于程序切片生成一个结构化候选漏洞。"
            "禁止只输出文件级可疑项，必须落到函数、行号、危险点和触发条件。"
            "只返回 JSON。"
        )
        user = json.dumps(
            {
                "slice": program_slice.__dict__,
                "schema": {
                    "title": "中文标题",
                    "vulnerability_type": "sql_injection|command_injection|path_traversal|unsafe_memory_copy|unsafe_c_string_api|code_execution|deserialization|other",
                    "severity": "critical|high|medium|low",
                    "description": "中文描述",
                    "trigger_conditions": ["条件1"],
                    "evidence": ["证据1"],
                    "confidence": 0.0,
                    "valid": True,
                    "llm_reasoning": "中文推理",
                },
            },
            ensure_ascii=False,
        )
        response = llm_client.chat(prompt, user, timeout=90)
        if not response.ok:
            return None
        raw = self._extract_json(response.content)
        if not isinstance(raw, dict):
            return None
        if not program_slice.function_name or not program_slice.line_start:
            raw["valid"] = False
        return VulnerabilityCandidate(
            id=self._id(program_slice.id, raw.get("title", "")),
            slice_id=program_slice.id,
            title=str(raw.get("title") or "候选漏洞"),
            vulnerability_type=str(raw.get("vulnerability_type") or self._type_from_sink(program_slice.sink)),
            severity=str(raw.get("severity") or "medium"),
            file_path=program_slice.file_path,
            line_start=program_slice.line_start,
            description=str(raw.get("description") or ""),
            trigger_conditions=[str(item) for item in raw.get("trigger_conditions", [])][:8],
            evidence=[str(item) for item in raw.get("evidence", [])][:12],
            confidence=float(raw.get("confidence") or 0.5),
            valid=bool(raw.get("valid", True)) and bool(program_slice.file_path and program_slice.line_start),
            llm_reasoning=str(raw.get("llm_reasoning") or response.content[:1000]),
        )

    def _fallback_candidate(self, program_slice: ProgramSlice) -> VulnerabilityCandidate:
        vuln_type = self._type_from_sink(program_slice.sink)
        return VulnerabilityCandidate(
            id=self._id(program_slice.id, vuln_type),
            slice_id=program_slice.id,
            title=f"{program_slice.function_name or program_slice.file_path} 存在 {vuln_type} 风险",
            vulnerability_type=vuln_type,
            severity="high" if vuln_type in {"command_injection", "unsafe_memory_copy"} else "medium",
            file_path=program_slice.file_path,
            line_start=program_slice.line_start,
            description="LLM 候选生成失败，系统基于危险函数和切片生成保守候选。",
            trigger_conditions=program_slice.controls or ["攻击者可控制输入并到达危险函数"],
            evidence=[program_slice.llm_summary, f"source={program_slice.source}", f"sink={program_slice.sink}"],
            confidence=0.45,
            valid=bool(program_slice.file_path and program_slice.line_start and program_slice.function_name),
            llm_reasoning=program_slice.llm_summary,
        )

    def _type_from_sink(self, sink: str) -> str:
        value = sink.lower()
        if "strcpy" in value or "strcat" in value or "sprintf" in value:
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
        return "other"

    def _extract_json(self, text: str) -> Any:
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

    def _id(self, slice_id: str, title: str) -> str:
        return hashlib.sha1(f"{slice_id}:{title}".encode("utf-8")).hexdigest()[:12]


class ClueAggregator:
    def aggregate(self, candidates: list[VulnerabilityCandidate]) -> list[VulnerabilityCandidate]:
        best: dict[tuple[str, int, str], VulnerabilityCandidate] = {}
        for candidate in candidates:
            if not candidate.valid:
                continue
            key = (candidate.file_path, candidate.line_start, candidate.vulnerability_type)
            current = best.get(key)
            if current is None or candidate.confidence > current.confidence:
                best[key] = candidate
            elif current:
                current.evidence.extend(item for item in candidate.evidence if item not in current.evidence)
                current.confidence = min(0.95, current.confidence + 0.05)
        return list(best.values())


class VulnerabilityClassifier:
    TAXONOMY = {
        "sql_injection": ("CWE-89", "A03:2021-Injection"),
        "command_injection": ("CWE-78", "A03:2021-Injection"),
        "path_traversal": ("CWE-22", "A01:2021-Broken Access Control"),
        "unsafe_memory_copy": ("CWE-787", "Memory Safety"),
        "unsafe_c_string_api": ("CWE-120", "Memory Safety"),
        "code_execution": ("CWE-94", "A03:2021-Injection"),
        "deserialization": ("CWE-502", "A08:2021-Software and Data Integrity Failures"),
    }

    def classify(
        self,
        candidates: list[VulnerabilityCandidate],
        slices: list[ProgramSlice],
        llm_client: DeepSeekClient,
    ) -> list[Finding]:
        slices_by_id = {item.id: item for item in slices}
        findings: list[Finding] = []
        for candidate in candidates:
            program_slice = slices_by_id.get(candidate.slice_id)
            if not program_slice:
                continue
            vuln_type, severity, summary = self._llm_classify(candidate, program_slice, llm_client)
            cwe, owasp = self.TAXONOMY.get(vuln_type, ("", ""))
            graph = self._chain_graph(candidate, program_slice)
            chain = [node.label for node in graph.nodes]
            findings.append(
                Finding(
                    id=candidate.id,
                    vulnerability_type=vuln_type,
                    severity=severity,
                    title=candidate.title,
                    description=candidate.description or summary,
                    file_path=candidate.file_path,
                    line_start=candidate.line_start,
                    code_snippet=program_slice.context,
                    source=program_slice.source,
                    sink=program_slice.sink,
                    call_chain=program_slice.call_chain,
                    evidence=candidate.evidence + [summary],
                    confidence=min(0.95, max(0.1, candidate.confidence)),
                    tool="agentic-mining",
                    recommendation="补充输入校验、长度/边界检查、参数化 API，并使用生成的 PoC/harness 复验。",
                    exploit_payloads=self._payloads_for(vuln_type),
                    exploit_chain=chain,
                    cwe=cwe,
                    owasp=owasp,
                    function_name=program_slice.function_name,
                    trigger_conditions=candidate.trigger_conditions,
                    slice_id=program_slice.id,
                    candidate_id=candidate.id,
                    chain_graph=graph,
                    chinese_summary=summary,
                )
            )
        return findings

    def _llm_classify(
        self,
        candidate: VulnerabilityCandidate,
        program_slice: ProgramSlice,
        llm_client: DeepSeekClient,
    ) -> tuple[str, str, str]:
        prompt = "你是漏洞类型判定智能体。请确认漏洞类型和严重性，并用中文给出最终摘要。只返回 JSON。"
        user = json.dumps({"candidate": candidate.__dict__, "slice": program_slice.__dict__}, ensure_ascii=False)
        response = llm_client.chat(prompt, user, timeout=90)
        if response.ok:
            try:
                raw = json.loads(re.search(r"\{.*\}", response.content, flags=re.S).group(0))  # type: ignore[union-attr]
                return (
                    str(raw.get("vulnerability_type") or candidate.vulnerability_type),
                    str(raw.get("severity") or candidate.severity),
                    str(raw.get("summary") or raw.get("description") or response.content[:1200]),
                )
            except (AttributeError, json.JSONDecodeError):
                return candidate.vulnerability_type, candidate.severity, response.content[:1200]
        return candidate.vulnerability_type, candidate.severity, f"LLM 类型判定失败: {response.error}"

    def _chain_graph(self, candidate: VulnerabilityCandidate, program_slice: ProgramSlice) -> ChainGraph:
        effect_label, effect_detail = self._effect_for(candidate, program_slice)
        nodes = [
            ChainNode("source", program_slice.source or "未知输入来源", "source", program_slice.file_path, program_slice.line_start),
            ChainNode("function", program_slice.function_name or program_slice.file_path, "function", program_slice.file_path, program_slice.line_start),
            ChainNode(
                "condition",
                "触发条件",
                "condition",
                detail="; ".join(candidate.trigger_conditions) or "攻击者输入满足约束后到达危险点",
            ),
            ChainNode("sink", program_slice.sink or candidate.vulnerability_type, "sink", program_slice.file_path, program_slice.line_start),
            ChainNode("effect", effect_label, "effect", detail=effect_detail),
        ]
        edges = [
            ChainEdge("source", "function", "passes_data", "输入进入函数"),
            ChainEdge("function", "condition", "guards", "受条件约束"),
            ChainEdge("condition", "sink", "reaches", "满足条件后到达危险点"),
            ChainEdge("sink", "effect", "triggers", "触发安全影响"),
        ]
        return ChainGraph(nodes=nodes, edges=edges)

    def _effect_for(self, candidate: VulnerabilityCandidate, program_slice: ProgramSlice) -> tuple[str, str]:
        mapping = {
            "sql_injection": ("SQL 注入影响", "可能导致绕过查询条件、读取或篡改数据库数据。"),
            "command_injection": ("命令执行影响", "攻击者控制的输入可能进入系统命令执行路径。"),
            "path_traversal": ("路径遍历影响", "攻击者可能读取或覆盖预期目录之外的文件。"),
            "unsafe_memory_copy": ("内存破坏影响", "边界不充分时可能触发越界读写、崩溃或代码执行。"),
            "unsafe_c_string_api": ("缓冲区溢出影响", "不安全 C 字符串 API 可能造成缓冲区溢出。"),
            "code_execution": ("代码执行影响", "攻击者输入可能被当作代码解释或执行。"),
            "deserialization": ("反序列化影响", "不可信对象可能触发任意对象构造或代码路径。"),
        }
        label, default_detail = mapping.get(candidate.vulnerability_type, ("安全影响", "需要结合验证证据确认实际影响。"))
        detail_parts = [
            candidate.description.strip(),
            default_detail,
            f"Sink: {program_slice.sink}" if program_slice.sink else "",
        ]
        detail = " ".join(part for part in detail_parts if part)[:500]
        return label, detail

    def _payloads_for(self, vuln_type: str) -> list[str]:
        mapping = {
            "sql_injection": ["' OR '1'='1", "1 UNION SELECT NULL", "1; SELECT sqlite_version();--"],
            "command_injection": ["127.0.0.1; id", "127.0.0.1 && whoami", "$(id)"],
            "path_traversal": ["../../../../etc/passwd", "..\\..\\..\\Windows\\win.ini"],
            "unsafe_memory_copy": ["A" * 4096],
            "unsafe_c_string_api": ["A" * 4096],
            "code_execution": ["__import__('os').system('id')"],
        }
        return mapping.get(vuln_type, ["manual-validation-payload"])
