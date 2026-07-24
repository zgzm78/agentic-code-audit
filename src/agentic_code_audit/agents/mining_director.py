"""MiningDirector — tactical commander for vulnerability mining.

The director sits between Recon and the Mining pipeline.  It receives
the project profile, available-tool inventory, and optional historical
verification feedback, then produces a MiningStrategy that influences:

- which tools run and at what priority
- which code areas / functions receive deeper analysis
- candidate prioritisation

All LLM outputs are validated by a rule engine before taking effect.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..llm import DeepSeekClient
from ..models import ProjectProfile, SemanticIndex, VerificationResult
from ..tools.runner import ToolAvailability


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ToolSelection:
    """A single tool selection in the mining strategy."""

    name: str
    priority: int = 1  # 1 = highest
    focus: str = ""  # optional sub-directory or file pattern
    extra_args: list[str] = field(default_factory=list)


@dataclass
class CodeExplorationTask:
    """An exploration task the LLM wants to perform."""

    action: str  # "read_file", "search_pattern", "trace_variable"
    path: str = ""
    start_line: int = 0
    end_line: int = 0
    pattern: str = ""
    directory: str = ""
    variable: str = ""
    function_name: str = ""


@dataclass
class CodeExplorationResult:
    """Result of a code exploration task."""

    task: CodeExplorationTask
    success: bool
    content: str = ""
    error: str = ""


@dataclass
class MiningStrategy:
    """Tactical mining plan produced by the MiningDirector."""

    # Tool layer
    tool_selections: list[ToolSelection] = field(default_factory=list)

    # Focus layer
    focus_directories: list[str] = field(default_factory=list)
    skip_patterns: list[str] = field(default_factory=list)
    priority_functions: list[str] = field(default_factory=list)
    parser_entries: list[str] = field(default_factory=list)
    taint_sources: list[str] = field(default_factory=list)
    focus_subsystems: list[str] = field(default_factory=list)

    # Verification hints
    build_attempt: bool = False
    harness_candidates: list[str] = field(default_factory=list)
    suggested_oracles: dict[str, str] = field(default_factory=dict)
    verification_hints: dict[str, dict[str, Any]] = field(default_factory=dict)
    dynamic_priority_functions: list[str] = field(default_factory=list)

    # Exploration
    code_exploration_tasks: list[CodeExplorationTask] = field(default_factory=list)
    confirmed_high_risk: list[dict[str, str]] = field(default_factory=list)
    dismissed_noise: list[dict[str, str]] = field(default_factory=list)
    rejected_strategy_items: list[dict[str, str]] = field(default_factory=list)
    exploration_log: list[dict[str, Any]] = field(default_factory=list)
    feedback_used: list[dict[str, str]] = field(default_factory=list)

    # Metadata
    initial_strategy: dict[str, Any] = field(default_factory=dict)
    strategy_effects: dict[str, Any] = field(default_factory=dict)
    rationale: str = ""
    confidence: float = 0.5
    validated: bool = False
    validation_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_selections": [
                {"name": ts.name, "priority": ts.priority, "focus": ts.focus, "extra_args": ts.extra_args}
                for ts in self.tool_selections
            ],
            "focus_directories": self.focus_directories,
            "skip_patterns": self.skip_patterns,
            "priority_functions": self.priority_functions,
            "parser_entries": self.parser_entries,
            "taint_sources": self.taint_sources,
            "focus_subsystems": self.focus_subsystems,
            "build_attempt": self.build_attempt,
            "harness_candidates": self.harness_candidates,
            "suggested_oracles": self.suggested_oracles,
            "verification_hints": self.verification_hints,
            "dynamic_priority_functions": self.dynamic_priority_functions,
            "confirmed_high_risk": self.confirmed_high_risk,
            "dismissed_noise": self.dismissed_noise,
            "rejected_strategy_items": self.rejected_strategy_items,
            "exploration_log": self.exploration_log,
            "feedback_used": self.feedback_used,
            "initial_strategy": self.initial_strategy,
            "strategy_effects": self.strategy_effects,
            "rationale": self.rationale,
            "confidence": self.confidence,
            "validated": self.validated,
            "validation_notes": self.validation_notes,
        }


# ---------------------------------------------------------------------------
# Code exploration tools (read-only, LLM can call these)
# ---------------------------------------------------------------------------

class CodeExplorationTools:
    """Read-only code exploration that the LLM can invoke during strategy formulation."""

    def __init__(self, target: Path, sandbox_container: str = ""):
        self.target = target.resolve()
        self.sandbox_container = sandbox_container or os.getenv(
            "AUDIT_SANDBOX_CONTAINER", "agentic-code-audit-sandbox"
        )
        self.log: list[dict[str, Any]] = []

    def _record(self, tool: str, args: dict[str, Any], result: str) -> None:
        self.log.append(
            {
                "tool": tool,
                "args": {key: str(value)[:160] for key, value in args.items()},
                "success": not result.startswith("[ERROR]"),
                "summary": self._summarize(result),
            }
        )

    def _summarize(self, value: str) -> str:
        lines = value.splitlines()
        if not lines:
            return ""
        head = " | ".join(line.strip() for line in lines[:3])
        suffix = f" ({len(lines)} lines)" if len(lines) > 3 else ""
        return (head + suffix)[:500]

    def _safe_path(self, path: str) -> Path | None:
        try:
            full = (self.target / path).resolve()
            full.relative_to(self.target)
            return full
        except (OSError, ValueError):
            return None

    def read_file(self, path: str, start: int = 0, end: int = 0) -> str:
        """Read *path* relative to the project root.  Optional start/end line numbers."""
        full = self._safe_path(path)
        if full is None:
            result = f"[ERROR] path escapes target root: {path}"
            self._record("read_file", {"path": path, "start": start, "end": end}, result)
            return result
        if not full.exists() or not full.is_file():
            result = f"[ERROR] file not found: {path}"
            self._record("read_file", {"path": path, "start": start, "end": end}, result)
            return result
        try:
            lines = full.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError as exc:
            result = f"[ERROR] cannot read {path}: {exc}"
            self._record("read_file", {"path": path, "start": start, "end": end}, result)
            return result
        if start > 0 or end > 0:
            start = max(1, start)
            end = min(len(lines), end) if end > 0 else len(lines)
            selected = lines[start - 1 : end]
        else:
            selected = lines[:200]  # cap at 200 lines by default
        result = "\n".join(f"{i + 1}: {line}" for i, line in enumerate(selected))
        self._record("read_file", {"path": path, "start": start, "end": end}, result)
        return result

    def search_pattern(self, pattern: str, directory: str = "") -> str:
        """Search *pattern* (regex) under *directory* using ripgrep (or sandbox)."""
        search_dir = self._safe_path(directory) if directory else self.target
        if search_dir is None:
            result = f"[ERROR] path escapes target root: {directory}"
            self._record("search_pattern", {"pattern": pattern, "directory": directory}, result)
            return result
        if not search_dir.exists():
            result = f"[ERROR] directory not found: {directory or '.'}"
            self._record("search_pattern", {"pattern": pattern, "directory": directory}, result)
            return result
        # Try host ripgrep first, then sandbox
        rg_paths = ["rg", "/usr/bin/rg"]
        rg_bin = None
        for candidate in rg_paths:
            try:
                proc = subprocess.run([candidate, "--version"], capture_output=True, timeout=5, check=False)
                if proc.returncode == 0:
                    rg_bin = candidate
                    break
            except (OSError, subprocess.TimeoutExpired):
                continue
        if not rg_bin:
            # try docker exec sandbox
            try:
                proc = subprocess.run(
                    ["docker", "exec", self.sandbox_container, "rg", "--version"],
                    capture_output=True, timeout=5, check=False,
                )
                if proc.returncode == 0:
                    rg_bin = "docker:exec:sandbox:rg"
            except (OSError, subprocess.TimeoutExpired):
                pass
        if not rg_bin:
            result = "[ERROR] ripgrep is not available (not on host and sandbox not reachable)."
            self._record("search_pattern", {"pattern": pattern, "directory": directory}, result)
            return result
        try:
            if rg_bin == "docker:exec:sandbox:rg":
                sandbox_dir = _translate_to_sandbox(str(search_dir))
                cmd = ["docker", "exec", self.sandbox_container, "rg", "-n", "--hidden",
                       "--glob", "!.git", "--glob", "!node_modules", pattern, sandbox_dir]
            else:
                cmd = [rg_bin, "-n", "--hidden", "--glob", "!.git", "--glob", "!node_modules", pattern, str(search_dir)]
            proc = subprocess.run(cmd, text=True, capture_output=True, timeout=30, check=False)
            output = proc.stdout.strip()
            if not output:
                result = f"No matches for pattern '{pattern}' in {directory or '.'}"
                self._record("search_pattern", {"pattern": pattern, "directory": directory}, result)
                return result
            lines = output.splitlines()
            result = "\n".join(lines[:80])  # cap results
            self._record("search_pattern", {"pattern": pattern, "directory": directory}, result)
            return result
        except (OSError, subprocess.TimeoutExpired) as exc:
            result = f"[ERROR] search failed: {exc}"
            self._record("search_pattern", {"pattern": pattern, "directory": directory}, result)
            return result

    def trace_variable(self, var_name: str, function_name: str, file_path: str) -> str:
        """Crude local trace: find definitions, assignments, and uses of *var_name* in *function_name*."""
        content = self.read_file(file_path)
        if content.startswith("[ERROR]"):
            return content
        lines = content.splitlines()
        in_func = False
        brace_depth = 0
        results: list[str] = []
        for line in lines:
            stripped = line.split(":", 1)[-1].strip() if ":" in line else line.strip()
            # Enter function
            if function_name in stripped and ("(" in stripped or "{" in stripped):
                in_func = True
            if not in_func:
                continue
            # Track brace depth for C-like languages
            brace_depth += stripped.count("{") - stripped.count("}")
            # Match variable
            if re.search(rf"\b{re.escape(var_name)}\b", stripped):
                tag = ""
                if re.search(rf"\b{re.escape(var_name)}\s*=", stripped):
                    tag = "  ← assign"
                elif re.search(rf"\b{re.escape(var_name)}\s*\[", stripped):
                    tag = "  ← index"
                elif re.search(rf"\bsizeof\s*\(\s*{re.escape(var_name)}\s*\)", stripped):
                    tag = "  ← sizeof"
                results.append(f"{line}{tag}")
            # Exit function
            if brace_depth <= 0 and in_func and stripped in ("}", "};", ");"):
                break
        if not results:
            result = f"No references to '{var_name}' found in function '{function_name}'."
            self._record("trace_variable", {"var_name": var_name, "function_name": function_name, "file_path": file_path}, result)
            return result
        result = "\n".join(results[:60])
        self._record("trace_variable", {"var_name": var_name, "function_name": function_name, "file_path": file_path}, result)
        return result

    def find_callers(self, function_name: str) -> str:
        """Find callers of *function_name* using ctags or text search."""
        return self._ctags_lookup(function_name, "callers")

    def find_callees(self, function_name: str) -> str:
        """Find callees of *function_name* using ctags or text search."""
        return self._ctags_lookup(function_name, "callees")

    def _ctags_lookup(self, function_name: str, direction: str) -> str:
        # Try sandbox ctags first, then fallback to grep
        try:
            proc = subprocess.run(
                ["docker", "exec", self.sandbox_container,
                 "bash", "-c",
                 f"grep -rn '\\b{function_name}\\b' /workspace/runs --include='*.c' --include='*.cpp' --include='*.h' -l 2>/dev/null | head -5"],
                text=True, capture_output=True, timeout=15, check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                files = proc.stdout.strip().splitlines()
                out_lines: list[str] = []
                for f in files[:5]:
                    try:
                        p2 = subprocess.run(
                            ["docker", "exec", self.sandbox_container,
                             "grep", "-n", f"\\b{function_name}\\b", f],
                            text=True, capture_output=True, timeout=10, check=False,
                        )
                        if p2.returncode == 0:
                            for line in p2.stdout.strip().splitlines()[:5]:
                                out_lines.append(f"{f}: {line}")
                    except (OSError, subprocess.TimeoutExpired):
                        continue
                if out_lines:
                    return f"{direction} of '{function_name}':\n" + "\n".join(out_lines[:30])
        except (OSError, subprocess.TimeoutExpired):
            pass
        return f"No {direction} found for '{function_name}' (ctags/sandbox unavailable)."


def _translate_to_sandbox(host_path: str) -> str:
    for backend_prefix, sandbox_prefix in [("/app/runs", "/workspace/runs"), ("/app/reports", "/workspace/reports")]:
        if host_path.startswith(backend_prefix):
            return sandbox_prefix + host_path[len(backend_prefix):]
    return host_path


# ---------------------------------------------------------------------------
# MiningDirector
# ---------------------------------------------------------------------------

MINING_DIRECTOR_PROMPT = """You are the tactical commander for a security audit. Your job is to formulate a mining strategy, NOT to find vulnerabilities directly.

## Project Profile
- Project type: {project_type}
- Languages: {languages}
- Total files: {total_files}
- Frameworks: {frameworks}
- Build systems: {build_systems}
- Entry points: {entry_points}
- High-risk files (top-10): {high_risk_files}
- Attack surfaces: {attack_surfaces}
- Package files: {package_files}
- Container files: {container_files}

## Available Tools (only these can be selected)
{available_tools}

## Historical Verification Feedback
{feedback}

## Your Task

Formulate a mining strategy as a single JSON object. The strategy should tell the static analysis pipeline:

1. **tool_selections**: Which tools from the available-tools list to use, with priority (1=highest, 3=lowest). For each tool you may optionally specify a sub-directory to focus on.
   - Example: [{{"name": "cppcheck", "priority": 1, "focus": "src/"}}, {{"name": "semgrep", "priority": 3}}]

2. **focus_directories**: Relative paths to prioritize (max 5). These must exist in the project.
   - Example: ["src/", "lib/parser/"]

3. **priority_functions**: Function names that warrant deeper analysis (max 8). Focus on parser entries, input handlers, and known-dangerous API users.
   - Example: ["readMetadata", "decodeJpeg", "parseExif"]

4. **parser_entries**: Functions that are likely parsing/decoding/deserializing entry points (max 5).
   - Example: ["jpeg_read_header", "tiff_parse_ifd"]

5. **taint_sources**: Variable/parameter names likely to carry attacker-controlled data (max 5).
   - Example: ["argv", "dataBuf", "inputStream"]

6. **focus_subsystems**: High-level subsystems to concentrate on (max 3).
   - Example: ["JPEG parser", "TIFF IFD handler"]

7. **build_attempt**: true/false — should we try to build C/C++ projects with CMake + ASAN/UBSAN?

8. **harness_candidates**: Functions (max 5) that are good candidates for generating a fuzzing harness.

9. **rationale**: A short paragraph explaining your strategy.

IMPORTANT:
- You may ONLY select tools from the "Available Tools" list. Do not invent tool names.
- focus_directories must be real paths in this project.
- If historical feedback says a previous verification was blocked (e.g., no binary), adjust strategy accordingly.
- If the project is a C/C++ parser/image library, PRIORITIZE cppcheck and clang-tidy over semgrep.
- Return ONLY the JSON object, no other text."""


class MiningDirector:
    """Tactical commander that uses LLM + rule validation to steer the mining pipeline.

    Supports two modes:
    1. **Multi-turn investigation** (recommended): LLM uses code exploration tools
       to read files, search patterns, and trace variables before forming a strategy.
    2. **Single-call strategy** (fallback): LLM outputs a JSON strategy in one shot.
    """

    # Multi-turn investigation system prompt
    INVESTIGATION_PROMPT = """你是资深安全审计指挥官。你的任务是对目标代码仓库进行深度调查，找出真正值得深挖的高风险区域。

你有以下代码探索工具:
- read_file(path, start_line, end_line): 读取源文件，可指定行范围
- search_pattern(regex, directory): 在指定目录中搜索模式（正则）
- trace_variable(name, function, file): 追踪变量的定义、赋值和使用
- find_callers(function): 查找函数的调用者
- list_directory(path): 列出目录结构

工作流程:
1. 先了解项目结构——查看关键目录和入口文件
2. 搜索危险函数——memcpy, strcpy, system, popen, exec, read, fread 等
3. 对发现的可疑点，读取相关代码上下文（特别是边界检查、输入来源）
4. 区分真正的代码漏洞和配置文件 lint 噪音
5. 汇总所有高风险确认点

每轮对话输出:
Thought: 当前分析状态和下一步计划
Action: 工具名
Action Input: {"参数": "值"}

当你认为调查已充分时:
Thought: 调查完成
Final Answer: {"focus_directories": [...], "priority_functions": [...], "confirmed_high_risk": [{"file":"...","function":"...","reason":"..."}], "dismissed_noise": [{"file":"...","reason":"..."}], "rationale": "整体策略说明"}"""

    def __init__(self, llm_client: DeepSeekClient):
        self.llm_client = llm_client
        self._exploration_tools: CodeExplorationTools | None = None

    # ------------------------------------------------------------------
    # Multi-turn investigation (primary mode)
    # ------------------------------------------------------------------

    def investigate(
        self,
        target: Path,
        profile: ProjectProfile,
        semantic_index: SemanticIndex,
        available_tools: list[ToolAvailability],
        historical_feedback: list[VerificationResult] | None = None,
        max_turns: int = 8,
    ) -> MiningStrategy:
        """Run multi-turn LLM investigation, then produce a validated strategy.

        The LLM autonomously explores the codebase using read_file, search_pattern,
        trace_variable, etc. before committing to a strategy.  This catches config-lint
        noise early and builds a richer understanding of real risk areas.
        """
        self._exploration_tools = CodeExplorationTools(target)
        tools = {
            "read_file": self._tool_read_file,
            "search_pattern": self._tool_search_pattern,
            "trace_variable": self._tool_trace_variable,
            "find_callers": self._tool_find_callers,
            "list_directory": self._tool_list_directory,
        }

        from ..llm import LLMAgent

        agent = LLMAgent(self.llm_client, self.INVESTIGATION_PROMPT, tools)
        task = self._build_investigation_task(target, profile, semantic_index, available_tools, historical_feedback)

        try:
            result_text = agent.run(task, max_turns=max_turns)
            strategy = self._parse_investigation_result(result_text)
            strategy.exploration_log = list(self._exploration_tools.log if self._exploration_tools else [])
            strategy.initial_strategy = strategy.to_dict()
            strategy.rationale = (
                f"[Multi-turn investigation, {len(agent.turns)} turns]\n"
                + agent.transcript[:1600]
            )
        except Exception:
            strategy = self.build_initial_strategy(
                target, profile, semantic_index, available_tools, historical_feedback
            )
        return self.apply_fallbacks(
            self.validate_strategy(strategy, target, available_tools, profile, semantic_index),
            target,
            profile,
            available_tools,
        )

    def _build_investigation_task(
        self,
        target: Path,
        profile: ProjectProfile,
        semantic_index: SemanticIndex,
        available_tools: list[ToolAvailability],
        historical_feedback: list[VerificationResult] | None = None,
    ) -> str:
        """Build the initial task description for the investigation agent."""
        tool_lines = [f"  - {t.name} ({t.capability}) [{'avail' if t.available else 'unavail'}]" for t in available_tools[:15]]
        build_systems = [str(e.get("type", "")) for e in (profile.build_entries or [])[:3] if e.get("type")]
        entry_points = [str(e.get("path", "") or e.get("binary", "")) for e in (profile.build_entries or [])[:5] if e]
        high_risk = profile.high_risk_files[:10] if profile.high_risk_files else []

        feedback_text = "无历史验证记录。"
        if historical_feedback:
            fb_lines = [f"  - {fb.get('finding_id', '?')}: status={fb.get('status', '?')}" for fb in historical_feedback[:3]]
            if fb_lines:
                feedback_text = "\n".join(fb_lines)

        return f"""开始调查以下项目:

## 项目概况
- 类型: {profile.project_type}
- 语言: {', '.join(f'{k}({v})' for k, v in sorted(profile.languages.items()))}
- 文件总数: {profile.total_files}
- 框架: {', '.join(profile.frameworks) if profile.frameworks else '未检测到'}
- 构建系统: {', '.join(build_systems) if build_systems else '未检测到'}
- 入口点: {', '.join(entry_points[:5]) if entry_points else '未检测到'}
- 高危文件提示: {', '.join(high_risk[:8]) if high_risk else '无'}
- 攻击面: {', '.join(profile.attack_surfaces[:5]) if profile.attack_surfaces else '无'}

## 可用工具
{chr(10).join(tool_lines) if tool_lines else '  (无)'}

## 历史验证反馈
{feedback_text}

请开始调查。先用 search_pattern 扫描高危函数，然后对关键文件进行深入阅读。"""

    # ------------------------------------------------------------------
    # Single-call strategy (fallback mode)
    # ------------------------------------------------------------------

    def formulate_strategy(
        self,
        target: Path,
        profile: ProjectProfile,
        semantic_index: SemanticIndex,
        available_tools: list[ToolAvailability],
        historical_feedback: list[VerificationResult] | None = None,
    ) -> MiningStrategy:
        """Produce a validated mining strategy (single LLM call, fallback mode)."""
        strategy = self.build_initial_strategy(target, profile, semantic_index, available_tools, historical_feedback)
        return self.apply_fallbacks(
            self.validate_strategy(strategy, target, available_tools, profile, semantic_index),
            target,
            profile,
            available_tools,
        )

    def build_initial_strategy(
        self,
        target: Path,
        profile: ProjectProfile,
        semantic_index: SemanticIndex,
        available_tools: list[ToolAvailability],
        historical_feedback: list[VerificationResult] | None = None,
    ) -> MiningStrategy:
        prompt = self._build_prompt(profile, semantic_index, available_tools, historical_feedback)
        try:
            response = self.llm_client.chat(
                "You are a precise security-audit strategist. Return only valid JSON matching the requested schema.",
                prompt,
                timeout=60,
            )
            strategy = self._parse_strategy(response.content if response.ok else "")
        except Exception:
            strategy = MiningStrategy()
        strategy.feedback_used = self._feedback_summary(historical_feedback)
        strategy.initial_strategy = strategy.to_dict()
        return strategy

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

    def _build_prompt(
        self,
        profile: ProjectProfile,
        semantic_index: SemanticIndex,
        available_tools: list[ToolAvailability],
        historical_feedback: list[VerificationResult] | None = None,
    ) -> str:
        # Available tools
        tool_lines: list[str] = []
        for tool in available_tools:
            status = "available" if tool.available else "unavailable"
            tool_lines.append(f"  - {tool.name} ({tool.capability}) [{status}]")
        tools_text = "\n".join(tool_lines) if tool_lines else "  (none)"

        # Build systems
        build_systems: list[str] = []
        if profile.build_entries:
            build_systems = [str(e.get("type", "")) for e in profile.build_entries[:3] if e.get("type")]
        if not build_systems:
            build_systems = [bs for bs in ["cmake", "make", "meson", "npm", "python"] if getattr(profile, f"{bs}_present", False)]

        # Entry points
        entry_points = [str(e.get("path", "") or e.get("binary", "")) for e in profile.build_entries[:5] if e]
        if not entry_points:
            entry_points = [str(e) for e in (profile.entry_points or [])[:5]]

        # Feedback
        feedback_text = "No prior verification runs."
        if historical_feedback:
            fb_lines: list[str] = []
            for fb in historical_feedback[:5]:
                fb_lines.append(f"  - {fb.get('finding_id', '?')}: status={fb.get('status', '?')}, method={fb.get('verification_method') or fb.get('method', '')}")
            if fb_lines:
                feedback_text = "\n".join(fb_lines)

        return MINING_DIRECTOR_PROMPT.format(
            project_type=profile.project_type,
            languages=", ".join(f"{lang} ({count})" for lang, count in sorted(profile.languages.items())),
            total_files=profile.total_files,
            frameworks=", ".join(profile.frameworks) if profile.frameworks else "none detected",
            build_systems=", ".join(build_systems) if build_systems else "none detected",
            entry_points=", ".join(entry_points[:5]) if entry_points else "none detected",
            high_risk_files=", ".join(profile.high_risk_files[:10]) if profile.high_risk_files else "none flagged",
            attack_surfaces=", ".join(profile.attack_surfaces[:8]) if profile.attack_surfaces else "none flagged",
            package_files=", ".join(profile.package_files[:5]) if profile.package_files else "none",
            container_files=", ".join(profile.container_files[:5]) if profile.container_files else "none",
            available_tools=tools_text,
            feedback=feedback_text,
        )

    # ------------------------------------------------------------------
    # LLM output parsing
    # ------------------------------------------------------------------

    def _parse_strategy(self, text: str) -> MiningStrategy:
        strategy = MiningStrategy()
        if not text.strip():
            return strategy

        # Extract JSON block
        json_text = text.strip()
        match = re.search(r"\{.*\}", json_text, flags=re.S)
        if match:
            json_text = match.group(0)

        try:
            raw = json.loads(json_text)
        except json.JSONDecodeError:
            return strategy

        # Tool selections
        for item in raw.get("tool_selections") or []:
            if isinstance(item, dict):
                strategy.tool_selections.append(ToolSelection(
                    name=str(item.get("name", "")),
                    priority=int(item.get("priority", 2)),
                    focus=str(item.get("focus", "")),
                    extra_args=list(item.get("extra_args", [])),
                ))

        # Simple list fields
        for field_name in ("focus_directories", "skip_patterns", "priority_functions",
                           "parser_entries", "taint_sources", "focus_subsystems",
                           "harness_candidates", "dynamic_priority_functions"):
            value = raw.get(field_name)
            if isinstance(value, list):
                setattr(strategy, field_name, [str(v) for v in value[:8]])

        # Scalar fields
        strategy.build_attempt = bool(raw.get("build_attempt", False))
        strategy.rationale = str(raw.get("rationale", ""))[:600]
        strategy.confidence = self._parse_confidence(raw.get("confidence", 0.5), default=0.5)

        # Oracle hints
        oracles = raw.get("suggested_oracles")
        if isinstance(oracles, dict):
            strategy.suggested_oracles = {str(k): str(v) for k, v in oracles.items()}
        strategy.confirmed_high_risk = self._dict_list(raw.get("confirmed_high_risk"), limit=12)
        strategy.dismissed_noise = self._dict_list(raw.get("dismissed_noise"), limit=12)
        hints = raw.get("verification_hints")
        if isinstance(hints, dict):
            strategy.verification_hints = {
                str(key): value if isinstance(value, dict) else {"hint": str(value)}
                for key, value in hints.items()
            }

        return strategy

    # ------------------------------------------------------------------
    # Rule-engine validation
    # ------------------------------------------------------------------

    def validate_strategy(
        self,
        strategy: MiningStrategy,
        target: Path,
        available_tools: list[ToolAvailability],
        profile: ProjectProfile,
        semantic_index: SemanticIndex | None = None,
    ) -> MiningStrategy:
        notes: list[str] = []
        available_names = {t.name for t in available_tools if getattr(t, "available", False)}
        all_tool_names = {t.name for t in available_tools}

        # --- validate tool selections ---
        valid_tools: list[ToolSelection] = []
        for ts in strategy.tool_selections:
            if not ts.name:
                continue
            if ts.name not in all_tool_names:
                self._reject(strategy, "tool", ts.name, "tool is not registered")
                continue
            if ts.name not in available_names:
                self._reject(strategy, "tool", ts.name, "tool is unavailable")
                continue
            # Ensure priority is within [1,3]
            ts.priority = max(1, min(3, ts.priority))
            valid_tools.append(ts)
        strategy.tool_selections = sorted(valid_tools, key=lambda item: (item.priority, item.name))

        # If LLM didn't select any tools, use defaults based on project type
        if not strategy.tool_selections:
            strategy.tool_selections = self._default_tools(profile, available_names)
            notes.append("No valid tool selections; using defaults based on project profile.")

        # --- validate focus directories ---
        valid_dirs: list[str] = []
        for d in strategy.focus_directories:
            rel = self._safe_relative_path(target, d)
            if rel and (target / rel).exists():
                valid_dirs.append(rel)
            else:
                self._reject(strategy, "focus_directory", d, "path does not exist or escapes target root")
        strategy.focus_directories = valid_dirs[:5]

        # --- validate priority functions ---
        known_functions = self._known_functions(target, semantic_index)
        strategy.priority_functions = self._valid_function_list(
            strategy, "priority_function", strategy.priority_functions, known_functions, limit=8
        )
        strategy.parser_entries = self._valid_function_list(
            strategy, "parser_entry", strategy.parser_entries, known_functions, limit=5, allow_keyword=True
        )
        strategy.taint_sources = strategy.taint_sources[:5]
        strategy.focus_subsystems = strategy.focus_subsystems[:3]
        strategy.harness_candidates = self._valid_function_list(
            strategy, "harness_candidate", strategy.harness_candidates, known_functions, limit=5
        )
        strategy.dynamic_priority_functions = self._valid_function_list(
            strategy, "dynamic_priority_function", strategy.dynamic_priority_functions, known_functions, limit=8, allow_keyword=True
        )
        strategy.dismissed_noise = self._validate_noise(strategy.dismissed_noise)
        strategy.confirmed_high_risk = self._validate_confirmed_risk(strategy, target, known_functions)

        # --- enforce C/C++ project defaults ---
        if profile is not None and profile.languages and any(lang in profile.languages for lang in ("C", "C++")):
            has_cpp_tool = any(ts.name in {"cppcheck", "clang-tidy"} for ts in strategy.tool_selections)
            cppcheck_available = "cppcheck" in available_names
            if not has_cpp_tool and cppcheck_available:
                strategy.tool_selections.append(ToolSelection(name="cppcheck", priority=1, focus=""))
                notes.append("C/C++ project detected; auto-added cppcheck (priority=1).")
            if profile.build_entries and "cmake" in available_names:
                strategy.build_attempt = True

        # --- clamp fields ---
        strategy.confidence = self._parse_confidence(strategy.confidence, default=0.5)
        strategy.validated = True
        strategy.validation_notes = notes

        return strategy

    def _validate_strategy(
        self,
        strategy: MiningStrategy,
        target: Path,
        available_tools: list[ToolAvailability],
        profile: ProjectProfile,
    ) -> MiningStrategy:
        return self.validate_strategy(strategy, target, available_tools, profile, None)

    def apply_fallbacks(
        self,
        strategy: MiningStrategy,
        target: Path,
        profile: ProjectProfile,
        available_tools: list[ToolAvailability],
    ) -> MiningStrategy:
        available_names = {t.name for t in available_tools if getattr(t, "available", False)}
        if not strategy.focus_directories:
            for candidate in ("src", "lib", "source", "app"):
                if (target / candidate).exists():
                    strategy.focus_directories.append(candidate)
                    break
        if not strategy.focus_directories:
            strategy.focus_directories = ["."]
        if not strategy.tool_selections:
            strategy.tool_selections = self._default_tools(profile, available_names)
        if any(lang in (profile.languages or {}) for lang in ("C", "C++")):
            if "parse" not in strategy.parser_entries:
                strategy.parser_entries.append("parse")
            if "decode" not in strategy.parser_entries:
                strategy.parser_entries.append("decode")
        strategy.validated = True
        return strategy

    def _default_tools(self, profile: ProjectProfile, available_names: set[str]) -> list[ToolSelection]:
        """Fallback tool selections when LLM produces nothing."""
        defaults: list[ToolSelection] = []
        priority = 1
        for name in ("semgrep", "gitleaks", "osv-scanner"):
            if name in available_names:
                defaults.append(ToolSelection(name=name, priority=priority))
                priority += 1
        if profile is not None and profile.languages and any(lang in profile.languages for lang in ("C", "C++", "Python")):
            if "cppcheck" in available_names:
                defaults.append(ToolSelection(name="cppcheck", priority=1))
            if "bandit" in available_names:
                defaults.append(ToolSelection(name="bandit", priority=2))
        return defaults

    def _reject(self, strategy: MiningStrategy, kind: str, value: str, reason: str) -> None:
        strategy.rejected_strategy_items.append({"kind": kind, "value": value, "reason": reason})

    def _safe_relative_path(self, target: Path, value: str) -> str:
        if not value:
            return ""
        try:
            full = (target / value).resolve()
            full.relative_to(target.resolve())
            return str(full.relative_to(target.resolve())).replace("\\", "/") or "."
        except (OSError, ValueError):
            return ""

    def _known_functions(self, target: Path, semantic_index: SemanticIndex | None) -> set[str]:
        names = {item.name for item in (semantic_index.functions if semantic_index else []) if item.name}
        if names:
            return names
        patterns = [
            r"\bdef\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
            r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
            r"(?:[\w:<>\*&]+\s+)+([A-Za-z_~][A-Za-z0-9_:~]*)\s*\([^;{}]*\)\s*(?:\{|$)",
        ]
        suffixes = {".py", ".js", ".ts", ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}
        for path in target.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in suffixes or ".git" in path.parts:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")[:200_000]
            except OSError:
                continue
            for pattern in patterns:
                names.update(match.group(1).split("::")[-1] for match in re.finditer(pattern, text))
        return names

    def _valid_function_list(
        self,
        strategy: MiningStrategy,
        kind: str,
        values: list[str],
        known_functions: set[str],
        limit: int,
        allow_keyword: bool = False,
    ) -> list[str]:
        output: list[str] = []
        keyword_allowlist = {"parse", "decode", "read", "load", "write", "metadata", "handler"}
        for value in values:
            item = str(value).strip()
            if not item:
                continue
            found = item in known_functions or any(item.lower() in fn.lower() for fn in known_functions)
            if not found and allow_keyword and item.lower() in keyword_allowlist:
                found = True
            if found:
                if item not in output:
                    output.append(item)
            else:
                self._reject(strategy, kind, item, "function was not found in semantic index or source text")
        return output[:limit]

    def _validate_noise(self, values: list[dict[str, str]]) -> list[dict[str, str]]:
        output: list[dict[str, str]] = []
        for item in values[:12]:
            file_path = str(item.get("file", "")).replace("\\", "/").lower()
            reason = str(item.get("reason", ""))[:240]
            if any(token in file_path for token in (".github/", "dependabot", "package-lock", "requirements", "cargo.lock")):
                output.append({"file": str(item.get("file", "")), "reason": reason or "static/config noise"})
        return output

    def _validate_confirmed_risk(
        self,
        strategy: MiningStrategy,
        target: Path,
        known_functions: set[str],
    ) -> list[dict[str, str]]:
        output: list[dict[str, str]] = []
        for item in strategy.confirmed_high_risk[:12]:
            file_path = str(item.get("file", "")).replace("\\", "/")
            function = str(item.get("function", ""))
            rel = self._safe_relative_path(target, file_path) if file_path else ""
            if file_path and not rel:
                self._reject(strategy, "confirmed_high_risk", file_path, "file does not exist or escapes target root")
                continue
            lowered = file_path.lower()
            if any(token in lowered for token in (".github/", "dependabot", "package-lock", "requirements", "cargo.lock")):
                self._reject(strategy, "confirmed_high_risk", file_path, "static/config/dependency/secret risk cannot be promoted as source_code")
                continue
            if function and known_functions and function not in known_functions and not any(function.lower() in fn.lower() for fn in known_functions):
                self._reject(strategy, "confirmed_high_risk", function, "function was not found")
                continue
            output.append(
                {
                    "file": rel or file_path,
                    "function": function,
                    "reason": str(item.get("reason", ""))[:240],
                }
            )
        return output

    def _dict_list(self, value: Any, limit: int) -> list[dict[str, str]]:
        if not isinstance(value, list):
            return []
        output: list[dict[str, str]] = []
        for item in value[:limit]:
            if isinstance(item, dict):
                output.append({str(key): str(val) for key, val in item.items()})
        return output

    def _feedback_summary(self, historical_feedback: list[VerificationResult] | None) -> list[dict[str, str]]:
        output: list[dict[str, str]] = []
        for item in (historical_feedback or [])[:8]:
            if isinstance(item, dict):
                output.append(
                    {
                        "finding_id": str(item.get("finding_id", "")),
                        "status": str(item.get("status", "")),
                        "runtime_type": str(item.get("runtime_type", "")),
                    }
                )
            else:
                output.append(
                    {
                        "finding_id": str(getattr(item, "finding_id", "")),
                        "status": str(getattr(item, "status", "")),
                        "runtime_type": str(getattr(item, "runtime_type", "")),
                    }
                )
        return output

    def _parse_confidence(self, value: Any, default: float = 0.5) -> float:
        if isinstance(value, (int, float)):
            return max(0.1, min(1.0, float(value)))
        text = str(value or "").strip().lower()
        labeled = {
            "critical": 0.95,
            "high": 0.8,
            "medium": 0.55,
            "moderate": 0.55,
            "low": 0.3,
            "weak": 0.25,
            "unknown": default,
        }
        if text in labeled:
            return labeled[text]
        try:
            return max(0.1, min(1.0, float(text)))
        except (TypeError, ValueError):
            return default

    # ------------------------------------------------------------------
    # Investigation tools (called by LLMAgent during multi-turn investigation)
    # ------------------------------------------------------------------

    def _tool_read_file(self, path: str = "", start_line: int = 0, end_line: int = 0) -> str:
        """Read a source file. Called by LLM during investigation."""
        if not self._exploration_tools:
            return "[ERROR] no target set"
        result = self._exploration_tools.read_file(path, start_line, end_line)
        # Truncate to avoid overflowing context
        lines = result.splitlines()
        if len(lines) > 150:
            return "\n".join(lines[:150]) + f"\n... ({len(lines) - 150} more lines)"
        return result

    def _tool_search_pattern(self, pattern: str = "", directory: str = "") -> str:
        """Search for regex pattern in the codebase."""
        if not self._exploration_tools:
            return "[ERROR] no target set"
        result = self._exploration_tools.search_pattern(pattern, directory)
        lines = result.splitlines()
        if len(lines) > 60:
            return "\n".join(lines[:60]) + f"\n... ({len(lines) - 60} more matches)"
        return result

    def _tool_trace_variable(self, name: str = "", function: str = "", file: str = "") -> str:
        """Trace a variable within a function."""
        if not self._exploration_tools:
            return "[ERROR] no target set"
        return self._exploration_tools.trace_variable(name, function, file)

    def _tool_find_callers(self, function: str = "") -> str:
        """Find callers of a function."""
        if not self._exploration_tools:
            return "[ERROR] no target set"
        return self._exploration_tools.find_callers(function)

    def _tool_list_directory(self, path: str = ".") -> str:
        """List directory contents."""
        if not self._exploration_tools:
            return "[ERROR] no target set"
        target = self._exploration_tools._safe_path(path)
        if target is None:
            result = "[ERROR] path escapes target root"
            self._exploration_tools._record("list_directory", {"path": path}, result)
            return result
        if not target.exists():
            result = f"[ERROR] directory not found: {path}"
            self._exploration_tools._record("list_directory", {"path": path}, result)
            return result
        entries = []
        try:
            for item in sorted(target.iterdir()):
                prefix = "[D]" if item.is_dir() else "[F]"
                entries.append(f"{prefix} {item.name}")
        except OSError as exc:
            result = f"[ERROR] {exc}"
            self._exploration_tools._record("list_directory", {"path": path}, result)
            return result
        output = "\n".join(entries)
        self._exploration_tools._record("list_directory", {"path": path}, output)
        if len(entries) > 80:
            return "\n".join(entries[:80]) + f"\n... ({len(entries) - 80} more)"
        return "\n".join(entries)

    def _parse_investigation_result(self, text: str) -> MiningStrategy:
        """Parse the investigation agent's final answer into a MiningStrategy."""
        strategy = MiningStrategy()
        if not text.strip():
            return strategy

        # Try to extract JSON from the final answer
        json_text = text.strip()
        match = re.search(r"\{.*\}", json_text, flags=re.S)
        if match:
            json_text = match.group(0)

        try:
            raw = json.loads(json_text)
        except json.JSONDecodeError:
            return strategy

        # Focus directories
        dirs = raw.get("focus_directories") or []
        if isinstance(dirs, list):
            strategy.focus_directories = [str(d) for d in dirs[:6]]

        # Priority functions
        funcs = raw.get("priority_functions") or []
        if isinstance(funcs, list):
            strategy.priority_functions = [str(f) for f in funcs[:10]]

        # Confirmed high risk areas → priority_functions + focus_directories
        for area in raw.get("confirmed_high_risk") or []:
            if isinstance(area, dict):
                fn = str(area.get("function", ""))
                if fn and fn not in strategy.priority_functions:
                    strategy.priority_functions.append(fn)
                fdir = str(area.get("file", ""))
                if fdir:
                    # Use parent directory as focus
                    parent = str(Path(fdir).parent) if fdir else ""
                    if parent and parent != "." and parent not in strategy.focus_directories:
                        strategy.focus_directories.append(parent)

        # Dismissed noise
        strategy.dismissed_noise = self._dict_list(raw.get("dismissed_noise"), limit=12)
        strategy.confirmed_high_risk = self._dict_list(raw.get("confirmed_high_risk"), limit=12)
        for field_name in ("parser_entries", "taint_sources", "harness_candidates", "dynamic_priority_functions"):
            value = raw.get(field_name)
            if isinstance(value, list):
                setattr(strategy, field_name, [str(v) for v in value[:8]])
        hints = raw.get("verification_hints")
        if isinstance(hints, dict):
            strategy.verification_hints = {
                str(key): value if isinstance(value, dict) else {"hint": str(value)}
                for key, value in hints.items()
            }

        # Rationale
        strategy.rationale = str(raw.get("rationale", ""))[:1000]
        strategy.confidence = self._parse_confidence(raw.get("confidence", 0.6), default=0.6)
        strategy.validated = True

        return strategy

    # ------------------------------------------------------------------
    # Candidate prioritisation
    # ------------------------------------------------------------------

    def prioritize_candidates(
        self,
        candidates: list[Any],  # VulnerabilityCandidate
        strategy: MiningStrategy,
        profile: Any | None = None,  # ProjectProfile
    ) -> list[Any]:
        """Sort candidates so high-priority (verifiable) ones come first.

        Weighting:
          - Direct function match with priority_functions: +10
          - Parser entry function match: +8
          - Function name partial match: +5
          - File in focus directory: +3
          - CLI/runtime entry file (buildable): +6
        """
        priority_set = set(strategy.priority_functions) if strategy.priority_functions else set()
        parser_set = set(strategy.parser_entries) if strategy.parser_entries else set()

        # Collect files that are runtime/CLI entries (more verifiable)
        runtime_files: set[str] = set()
        if profile is not None:
            for entry in (getattr(profile, "runtime_entries", None) or []):
                if isinstance(entry, dict):
                    f = entry.get("file", "")
                    if f:
                        runtime_files.add(f)
            for entry in (getattr(profile, "build_entries", None) or []):
                if isinstance(entry, dict):
                    f = entry.get("file", "")
                    if f and ("cmake" in entry.get("kind", "") or "native" in entry.get("kind", "")):
                        runtime_files.add(f)

        def _score(candidate: Any) -> int:
            score = 0
            fn = str(getattr(candidate, "function_name", "") or "")
            fp = str(getattr(candidate, "file_path", "") or "")
            # Direct function match
            if fn and fn in priority_set:
                score += 10
            # Parser entry match (highest verifiability boost for parser projects)
            for pe in parser_set:
                if pe.lower() in fn.lower():
                    score += 8
                    break
            # Partial function name match
            if score < 10:
                for pf in priority_set:
                    if pf.lower() in fn.lower():
                        score += 5
                        break
            # Runtime/CLI entry file — buildable and runnable
            if fp in runtime_files:
                score += 6
            elif any(fp.endswith(suffix) for suffix in (".c", ".cpp", ".cc")):
                # C/C++ source files get a small baseline boost
                for d in strategy.focus_directories:
                    if fp.startswith(d):
                        score += 3
                        break
            # File in a focus directory
            for d in strategy.focus_directories:
                if fp.startswith(d):
                    score += 3
                    break
            # Tool-sourced candidates are more reliable
            source = getattr(candidate, "candidate_source", "") or ""
            if source == "tool":
                score += 2
            elif source == "rule":
                score += 1
            return score

        for candidate in candidates:
            self._annotate_candidate(candidate, strategy, runtime_files)
        return sorted(candidates, key=lambda item: getattr(item, "director_priority", 0), reverse=True)

    def _annotate_candidate(
        self,
        candidate: Any,
        strategy: MiningStrategy,
        runtime_files: set[str],
    ) -> None:
        score = 0
        reasons: list[str] = []
        fn = str(getattr(candidate, "function_name", "") or "")
        fp = str(getattr(candidate, "file_path", "") or "")
        for item in strategy.priority_functions:
            if fn and item.lower() in fn.lower():
                score += 10 if fn == item else 5
                reasons.append(f"priority_function:{item}")
                break
        for item in strategy.parser_entries:
            if fn and item.lower() in fn.lower():
                score += 8
                reasons.append(f"parser_entry:{item}")
                break
        for item in strategy.dynamic_priority_functions:
            if fn and item.lower() in fn.lower():
                score += 6
                reasons.append(f"dynamic_priority:{item}")
                break
        if fp in runtime_files:
            score += 6
            reasons.append("runtime_entry_file")
        for directory in strategy.focus_directories:
            prefix = directory.rstrip("/")
            if prefix in {"", "."} or fp == prefix or fp.startswith(prefix + "/"):
                score += 3
                reasons.append(f"focus_dir:{directory}")
                break
        source = getattr(candidate, "candidate_source", "") or ""
        if source == "tool":
            score += 2
            reasons.append("tool_candidate")
        elif source == "rule":
            score += 1
            reasons.append("rule_candidate")
        setattr(candidate, "director_priority", score)
        setattr(candidate, "director_reason", "; ".join(reasons) or "default_order")
        hint = self._hint_for_candidate(candidate, strategy)
        if hint:
            setattr(candidate, "verification_hint", hint)
        assumptions = getattr(candidate, "assumptions", None)
        if isinstance(assumptions, list):
            assumptions.append(f"director_score={score}")
            assumptions.append(f"director_reason={getattr(candidate, 'director_reason', '')}")

    def _hint_for_candidate(self, candidate: Any, strategy: MiningStrategy) -> dict[str, Any]:
        fn = str(getattr(candidate, "function_name", "") or "")
        if fn and fn in strategy.verification_hints:
            return strategy.verification_hints[fn]
        for key, hint in strategy.verification_hints.items():
            if key and key.lower() in fn.lower():
                return hint
        return {}
