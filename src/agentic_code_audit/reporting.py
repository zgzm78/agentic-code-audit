from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import AuditReport, Finding, VerificationResult


class ReportAgent:
    """Generate human-readable reports from persisted audit evidence."""

    def write(self, report: AuditReport, output_dir: Path) -> tuple[Path, Path]:
        output_dir.mkdir(parents=True, exist_ok=True)
        json_path = output_dir / "audit-report.json"
        md_path = output_dir / "audit-report.md"
        json_path.write_text(json.dumps(self.to_json(report), ensure_ascii=False, indent=2), encoding="utf-8")
        md_path.write_text(self.to_markdown(report), encoding="utf-8")
        return json_path, md_path

    def to_json(self, report: AuditReport) -> dict[str, Any]:
        return report.to_dict()

    def to_markdown(self, report: AuditReport) -> str:
        verification_by_finding = {item.finding_id: item for item in report.verification_results}
        lines: list[str] = [
            "# 智能体源码安全审计报告",
            "",
            "## 任务摘要",
            "",
            f"- 审计目标: `{report.input_source.original}`",
            f"- 目标类型: `{report.input_source.kind}`",
            f"- 本地路径: `{report.target}`",
            f"- Commit: `{report.input_source.commit or 'n/a'}`",
            f"- 生成时间: `{report.created_at}`",
            f"- 模型供应商: `{report.llm_provider}`",
            f"- 模型名称: `{report.llm_model}`",
            f"- 漏洞数量: `{len(report.findings)}`",
            f"- 验证尝试: `{len(report.verification_results)}`",
            "",
            "## 项目画像",
            "",
            f"- 项目类型: `{report.profile.project_type}`",
            f"- 语言: `{report.profile.languages}`",
            f"- 框架: `{', '.join(report.profile.frameworks) or 'unknown'}`",
            f"- 包管理/构建文件: `{', '.join(report.profile.package_files) or 'none'}`",
            f"- 攻击面: `{', '.join(report.profile.attack_surfaces) or 'none'}`",
            f"- 推荐工具: `{', '.join(report.profile.recommended_tools) or 'none'}`",
            f"- 构建入口数: `{len(report.profile.build_entries)}`",
            f"- 运行入口数: `{len(report.profile.runtime_entries)}`",
            f"- 测试入口数: `{len(report.profile.test_entries)}`",
            f"- 验证入口数: `{len(report.profile.verification_entries)}`",
            f"- 弱化验证策略: `{', '.join(report.profile.weak_verification_strategies) or 'none'}`",
            f"- 攻击优先级: `{', '.join(report.profile.attack_priorities) or 'none'}`",
            f"- 验证提示: `{', '.join(report.profile.verification_hints) or 'none'}`",
            f"- 文件总数: `{report.profile.total_files}`",
            f"- 已扫描文件: `{report.profile.scanned_files}`",
            "",
        ]
        self._append_profile_entries(lines, "构建入口", report.profile.build_entries)
        self._append_profile_entries(lines, "运行入口", report.profile.runtime_entries)
        self._append_profile_entries(lines, "测试入口", report.profile.test_entries)
        self._append_profile_entries(lines, "验证入口", report.profile.verification_entries)

        lines.extend(
            [
                "## 工具执行",
                "",
            ]
        )
        if not report.tool_results:
            lines.append("- 未执行外部工具。")
        for result in report.tool_results:
            command = " ".join(result.command) if result.command else "n/a"
            artifacts = ", ".join(
                ref for ref in [result.stdout_artifact_id, result.stderr_artifact_id, result.parsed_artifact_id] if ref
            )
            lines.append(
                f"- `{result.tool}`: **{result.status}**; exit=`{result.exit_code}`; "
                f"cache_hit=`{result.cache_hit}`; command=`{command}`; artifacts=`{artifacts or 'none'}`; {result.summary}"
            )

        lines.extend(
            [
                "",
                "## 挖掘流水线",
                "",
                f"- 危险函数定位: `{len(report.dangerous_functions)}`",
                f"- 切片分析: `{len(report.program_slices)}`",
                f"- 候选漏洞生成: `{len(report.candidates)}`",
                f"- 最终漏洞判定: `{len(report.findings)}`",
                "",
            ]
        )
        if report.dangerous_functions:
            lines.append("### 危险函数样例")
            for item in report.dangerous_functions[:20]:
                refs = ", ".join(item.tool_run_refs or item.artifact_refs)
                lines.append(
                    f"- `{item.file_path}:{item.line_start}` `{item.function_name or 'unknown'}` "
                    f"-> `{item.dangerous_api}` ({item.category}); refs=`{refs or 'none'}`"
                )
            lines.append("")

        lines.extend(["## 漏洞详情", ""])
        if not report.findings:
            lines.append("未发现可进入报告的漏洞。")
        for finding in report.findings:
            self._append_finding(lines, finding, verification_by_finding.get(finding.id))

        lines.extend(["## 验证证据", ""])
        if not report.verification_results:
            lines.append("暂无验证尝试。")
        for verification in report.verification_results:
            self._append_verification(lines, verification)

        self._append_artifact_index(lines, report)
        self._append_fix_summary(lines, report.findings)
        return "\n".join(lines).rstrip() + "\n"

    def _append_profile_entries(self, lines: list[str], title: str, entries: list[dict[str, Any]]) -> None:
        if not entries:
            return
        lines.extend([f"### {title}", ""])
        for entry in entries[:20]:
            lines.append(
                f"- `{entry.get('kind', 'entry')}` `{entry.get('file') or entry.get('file_path') or 'n/a'}` "
                f"command=`{entry.get('command', 'n/a')}` evidence={entry.get('evidence', 'n/a')}"
            )
        lines.append("")

    def _append_finding(
        self,
        lines: list[str],
        finding: Finding,
        verification: VerificationResult | None,
    ) -> None:
        lines.extend(
            [
                f"### {finding.id} - {finding.title}",
                "",
                f"- 类型: `{finding.vulnerability_type}`",
                f"- 严重性: `{finding.severity}`",
                f"- 置信度: `{finding.confidence:.2f}`",
                f"- 证据强度: `{finding.evidence_strength}`",
                f"- 可达性: `{finding.reachability or 'unknown'}`",
                f"- 可利用性: `{finding.exploitability or 'unknown'}`",
                f"- 建议验证: `{finding.should_verify}`",
                f"- 验证状态: `{verification.status if verification else 'not_verified'}`",
                f"- 位置: `{finding.file_path}:{finding.line_start or ''}`",
                f"- 函数: `{finding.function_name or 'unknown'}`",
                f"- Source: `{finding.source or 'unknown'}`",
                f"- Sink: `{finding.sink or 'unknown'}`",
                f"- CWE: `{finding.cwe or 'n/a'}`",
                f"- OWASP: `{finding.owasp or 'n/a'}`",
                f"- candidate_id: `{finding.candidate_id or 'n/a'}`",
                f"- slice_id: `{finding.slice_id or 'n/a'}`",
                f"- dangerous_function_id: `{finding.dangerous_function_id or 'n/a'}`",
                f"- tool_run_refs: `{', '.join(finding.tool_run_refs) or 'none'}`",
                f"- artifact_refs: `{', '.join(finding.artifact_refs) or 'none'}`",
                "",
                "#### 摘要",
                "",
                finding.chinese_summary or finding.description or "无摘要。",
                "",
                "#### 触发链路",
                "",
            ]
        )
        if finding.exploit_chain:
            for step in finding.exploit_chain:
                lines.append(f"- {step}")
        else:
            lines.append("- 暂无触发链路描述。")
        if finding.chain_graph.nodes:
            lines.extend(["", "```mermaid", self._chain_mermaid(finding), "```"])
        if finding.trigger_conditions:
            lines.extend(["", "#### 触发条件", ""])
            lines.extend(f"- {condition}" for condition in finding.trigger_conditions)
        if finding.exploit_payloads:
            lines.extend(["", "#### PoC/复现输入", ""])
            lines.extend(f"- `{payload}`" for payload in finding.exploit_payloads)
        lines.extend(["", "#### 静态证据", ""])
        if finding.evidence:
            lines.extend(f"- {evidence}" for evidence in finding.evidence)
        else:
            lines.append("- 暂无静态证据。")
        if finding.code_snippet:
            lines.extend(["", "#### 代码片段", "", "```", finding.code_snippet, "```"])
        lines.extend(["", "#### 修复建议", "", finding.recommendation or "结合上下文补充输入验证、边界检查和回归测试。", ""])

    def _append_verification(self, lines: list[str], verification: VerificationResult) -> None:
        command = " ".join(verification.target_command) if verification.target_command else "n/a"
        sandbox_command = " ".join(verification.sandbox_command) if verification.sandbox_command else "n/a"
        lines.extend(
            [
                f"### {verification.finding_id}",
                "",
                f"- 状态: `{verification.status}`",
                f"- 方法: `{verification.method}`",
                f"- 策略: `{verification.strategy or 'n/a'}`",
                f"- 运行类型: `{verification.runtime_type or 'n/a'}`",
                f"- 本地 fallback: `{verification.local_fallback}`",
                f"- 验证模式: `{verification.verification_mode or 'n/a'}`",
                f"- Oracle: {verification.oracle or 'n/a'}",
                f"- 目标命令: `{command}`",
                f"- 沙箱命令: `{sandbox_command}`",
                f"- PoC: `{verification.poc_path or 'n/a'}`",
                f"- 复现结论: {verification.reproduction or verification.checker_summary or 'n/a'}",
                f"- evidence_artifact_ids: `{', '.join(verification.evidence_artifact_ids) or 'none'}`",
                f"- exploit_artifact_ids: `{', '.join(verification.exploit_artifact_ids) or 'none'}`",
                "",
            ]
        )
        self._append_list(lines, "环境缺口", verification.environment_gaps)
        self._append_json_section(lines, "验证计划", verification.verification_plan)
        self._append_json_section(lines, "环境画像", verification.environment)
        self._append_json_section(lines, "执行记录", verification.execution)
        self._append_json_section(lines, "Checker 判定", verification.checker_details)
        self._append_list(lines, "证据摘要", verification.evidence)
        if verification.generated_artifacts:
            self._append_list(lines, "生成文件", verification.generated_artifacts)
        if verification.exit_code is not None:
            lines.append(f"- 退出码: `{verification.exit_code}`")
        if verification.stdout_excerpt:
            lines.extend(["", "Stdout:", "", "```", verification.stdout_excerpt, "```"])
        if verification.stderr_excerpt:
            lines.extend(["", "Stderr:", "", "```", verification.stderr_excerpt, "```"])
        if verification.http_status:
            lines.append(f"- HTTP 状态码: `{verification.http_status}`")
        if verification.http_evidence:
            lines.extend(["", "HTTP 证据:", "", "```", verification.http_evidence, "```"])
        lines.append("")

    def _append_artifact_index(self, lines: list[str], report: AuditReport) -> None:
        records = []
        for result in report.tool_results:
            records.extend(result.artifact_records)
        for verification in report.verification_results:
            records.extend(verification.artifact_records)
        lines.extend(["## Artifact 索引", ""])
        if not records:
            lines.append("暂无 artifact 记录。")
            lines.append("")
            return
        seen: set[str] = set()
        for record in records:
            if record.id in seen:
                continue
            seen.add(record.id)
            lines.append(
                f"- `{record.id}` `{record.kind}` path=`{record.path}` "
                f"sha256=`{record.sha256 or 'n/a'}` size=`{record.size_bytes}`"
            )
        lines.append("")

    def _append_fix_summary(self, lines: list[str], findings: list[Finding]) -> None:
        lines.extend(["## 修复建议", ""])
        if not findings:
            lines.append("暂无修复建议。")
            return
        for finding in findings:
            lines.append(f"- `{finding.id}` {finding.recommendation or '结合上下文补充输入验证、边界检查和回归测试。'}")

    def _append_list(self, lines: list[str], title: str, values: list[str]) -> None:
        if not values:
            return
        lines.extend([f"#### {title}", ""])
        lines.extend(f"- {value}" for value in values)
        lines.append("")

    def _append_json_section(self, lines: list[str], title: str, data: dict[str, Any]) -> None:
        if not data:
            return
        lines.extend([f"#### {title}", "", "```json", json.dumps(data, ensure_ascii=False, indent=2), "```", ""])

    def _chain_mermaid(self, finding: Finding) -> str:
        lines = ["flowchart LR"]
        for node in finding.chain_graph.nodes:
            label = node.label
            if node.file_path:
                label += f"\\n{node.file_path}:{node.line or ''}"
            if node.detail:
                label += f"\\n{node.detail[:120]}"
            safe_label = label.replace('"', "'")
            lines.append(f'  {node.id}["{safe_label}"]')
        for edge in finding.chain_graph.edges:
            label = (edge.label or edge.type).replace('"', "'")
            lines.append(f'  {edge.source} -- "{label}" --> {edge.target}')
        return "\n".join(lines)


class ReportWriter:
    """Compatibility entrypoint used by the existing pipeline and CLI."""

    def __init__(self) -> None:
        self.agent = ReportAgent()

    def write(self, report: AuditReport, output_dir: Path) -> tuple[Path, Path]:
        return self.agent.write(report, output_dir)

    def _to_markdown(self, report: AuditReport) -> str:
        return self.agent.to_markdown(report)
