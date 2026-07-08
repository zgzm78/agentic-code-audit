from __future__ import annotations

import json
from pathlib import Path

from .models import AuditReport


class ReportWriter:
    def write(self, report: AuditReport, output_dir: Path) -> tuple[Path, Path]:
        output_dir.mkdir(parents=True, exist_ok=True)
        json_path = output_dir / "audit-report.json"
        md_path = output_dir / "audit-report.md"
        json_path.write_text(
            json.dumps(report.to_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        md_path.write_text(self._to_markdown(report), encoding="utf-8")
        return json_path, md_path

    def _to_markdown(self, report: AuditReport) -> str:
        lines = [
            "# 智能体源码安全审计报告",
            "",
            f"- 审计目标: `{report.input_source.original}`",
            f"- 目标类型: `{report.input_source.kind}`",
            f"- 本地路径: `{report.target}`",
            f"- Commit: `{report.input_source.commit or 'n/a'}`",
            f"- 生成时间: `{report.created_at}`",
            f"- DeepSeek: `{report.llm_enabled}`",
            "",
            "## Agent 执行流程",
            "",
        ]
        for event in report.agent_events:
            lines.append(f"- `{event.agent}` / `{event.action}`: **{event.status}** {event.detail}")

        lines.extend(
            [
                "",
                "## 项目画像",
                "",
                f"- 语言: `{report.profile.languages}`",
                f"- 框架: `{', '.join(report.profile.frameworks) or 'unknown'}`",
                f"- 包管理/构建文件: `{', '.join(report.profile.package_files) or 'none'}`",
                f"- 攻击面: `{', '.join(report.profile.attack_surfaces) or 'none'}`",
                f"- 推荐工具: `{', '.join(report.profile.recommended_tools) or 'none'}`",
                f"- 文件总数: `{report.profile.total_files}`",
                f"- 已扫描文件: `{report.profile.scanned_files}`",
                "",
                "## 语义索引",
                "",
                f"- 函数数: `{len(report.semantic_index.functions)}`",
                f"- 路由数: `{len(report.semantic_index.routes)}`",
                f"- Source 符号: `{', '.join(report.semantic_index.source_symbols) or 'none'}`",
                f"- Sink 符号: `{', '.join(report.semantic_index.sink_symbols) or 'none'}`",
                "",
            ]
        )

        if report.semantic_index.routes:
            lines.append("路由样例:")
            for route in report.semantic_index.routes[:50]:
                lines.append(f"- `{route.method} {route.route}` -> `{route.handler}` ({route.file_path}:{route.line_start})")
            lines.append("")

        lines.extend(["## 工具执行结果", ""])
        for result in report.tool_results:
            command = " ".join(result.command) if result.command else ""
            lines.append(f"- `{result.tool}`: **{result.status}** {result.summary} `{command}`")

        lines.extend(["", "## 漏洞挖掘流水线", ""])
        lines.append(f"- 危险函数定位: `{len(report.dangerous_functions)}`")
        lines.append(f"- 切片分析: `{len(report.program_slices)}`")
        lines.append(f"- 候选漏洞生成: `{len(report.candidates)}`")
        lines.append(f"- 最终漏洞判定: `{len(report.findings)}`")
        if report.dangerous_functions:
            lines.extend(["", "### 危险函数样例", ""])
            for item in report.dangerous_functions[:20]:
                lines.append(
                    f"- `{item.file_path}:{item.line_start}` `{item.function_name or 'unknown'}` "
                    f"-> `{item.dangerous_api}` ({item.category})"
                )

        lines.extend(["", "## 漏洞详情", ""])
        if not report.findings:
            lines.append("未发现候选漏洞。")
        for finding in report.findings:
            lines.extend(
                [
                    f"### {finding.id} - {finding.title}",
                    "",
                    f"- 类型: `{finding.vulnerability_type}`",
                    f"- 严重性: `{finding.severity}`",
                    f"- 置信度: `{finding.confidence:.2f}`",
                    f"- 位置: `{finding.file_path}:{finding.line_start or ''}`",
                    f"- 路由: `{finding.route or 'n/a'}`",
                    f"- 工具: `{finding.tool}`",
                    f"- CWE: `{finding.cwe or 'n/a'}`",
                    f"- OWASP: `{finding.owasp or 'n/a'}`",
                    f"- Source: `{finding.source or 'unknown'}`",
                    f"- Sink: `{finding.sink or 'unknown'}`",
                    f"- 函数: `{finding.function_name or 'unknown'}`",
                    f"- 修复建议: {finding.recommendation or '需要结合上下文修复。'}",
                    f"- 摘要: {finding.chinese_summary or finding.description}",
                    "",
                    "触发/利用链:",
                ]
            )
            for step in finding.exploit_chain:
                lines.append(f"- {step}")
            if finding.trigger_conditions:
                lines.extend(["", "触发条件:"])
                for condition in finding.trigger_conditions:
                    lines.append(f"- {condition}")
            if finding.chain_graph.nodes:
                lines.extend(["", "链路图:", "", "```mermaid", self._chain_mermaid(finding), "```"])
            if finding.exploit_payloads:
                lines.extend(["", "Payloads:"])
                for payload in finding.exploit_payloads:
                    lines.append(f"- `{payload}`")
            lines.extend(["", "证据:"])
            for evidence in finding.evidence:
                lines.append(f"- {evidence}")
            if finding.code_snippet:
                lines.extend(["", "```", finding.code_snippet, "```", ""])

        lines.extend(["", "## 漏洞验证", ""])
        for verification in report.verification_results:
            lines.extend(
                [
                    f"### {verification.finding_id}",
                    "",
                    f"- 状态: `{verification.status}`",
                    f"- 方法: `{verification.method}`",
                    f"- 静态判定: `{verification.analysis_verdict or 'n/a'}`",
                    f"- 运行形态: `{verification.runtime_type or 'n/a'}`",
                    f"- 入口: `{verification.entry_point or 'n/a'}`",
                    f"- 触发类型: `{verification.trigger_type or 'n/a'}`",
                    f"- 验证模式: `{verification.verification_mode or 'n/a'}`",
                    f"- Oracle: {verification.oracle or 'n/a'}",
                    f"- 验证说明: {verification.verification_method or 'n/a'}",
                    f"- PoC: `{verification.poc_path or 'n/a'}`",
                    f"- 目标命令: `{' '.join(verification.target_command) if verification.target_command else 'n/a'}`",
                    f"- 沙箱命令: `{' '.join(verification.sandbox_command) if verification.sandbox_command else 'n/a'}`",
                    f"- 复现结论: {verification.reproduction}",
                    "",
                ]
            )
            if verification.verification_plan:
                lines.extend(["验证计划:", "", "```json", json.dumps(verification.verification_plan, ensure_ascii=False, indent=2), "```", ""])
            for evidence in verification.evidence:
                lines.append(f"- {evidence}")
            if verification.generated_artifacts:
                lines.extend(["", "生成文件:"])
                for artifact in verification.generated_artifacts:
                    lines.append(f"- `{artifact}`")
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
        return "\n".join(lines)

    def _chain_mermaid(self, finding) -> str:
        lines = ["flowchart LR"]
        for node in finding.chain_graph.nodes:
            label = f"{node.label}"
            if node.file_path:
                label += f"\\n{node.file_path}:{node.line or ''}"
            if node.detail:
                label += f"\\n{node.detail[:120]}"
            safe_label = label.replace('"', "'")
            lines.append(f'  {node.id}["{safe_label}"]')
        for edge in finding.chain_graph.edges:
            label = edge.label or edge.type
            lines.append(f'  {edge.source} -- "{label}" --> {edge.target}')
        return "\n".join(lines)
