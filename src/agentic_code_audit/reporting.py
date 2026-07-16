from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import AuditReport, Finding, VerificationResult


class ReportAgent:
    """Generate JSON and Markdown reports from persisted audit evidence."""

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
            "# Agentic Code Audit 安全审计报告",
            "",
            "---",
            "",
            "## 报告信息",
            "",
            "| 属性 | 内容 |",
            "|----------|-------|",
            f"| **审计目标** | `{report.input_source.original}` |",
            f"| **目标类型** | `{report.input_source.kind}` |",
            f"| **本地路径** | `{report.target}` |",
            f"| **Commit** | `{report.input_source.commit or 'n/a'}` |",
            f"| **生成时间** | {report.created_at} |",
            f"| **运行模式** | `{getattr(report, 'mode', 'standard')}` |",
            f"| **模型** | `{report.llm_provider}/{report.llm_model}` |",
            f"| **候选漏洞** | {len(report.candidates)} |",
            f"| **最终漏洞** | {len(report.findings)} |",
            f"| **验证尝试** | {len(report.verification_results)} |",
            "",
        ]
        self._append_executive_summary(lines, report, verification_by_finding)
        lines.extend(
            [
                "## 项目画像",
                "",
                f"- **项目类型:** `{report.profile.project_type}`",
                f"- **语言:** `{self._format_dict(report.profile.languages)}`",
                f"- **框架:** `{', '.join(report.profile.frameworks) or 'unknown'}`",
                f"- **包管理/构建文件:** `{', '.join(report.profile.package_files) or 'none'}`",
                f"- **攻击面:** `{', '.join(report.profile.attack_surfaces) or 'none'}`",
                f"- **推荐工具:** `{', '.join(report.profile.recommended_tools) or 'none'}`",
                f"- **攻击优先级:** `{', '.join(report.profile.attack_priorities) or 'none'}`",
                f"- **验证提示:** `{', '.join(report.profile.verification_hints) or 'none'}`",
                f"- **分析文件数:** `{report.profile.scanned_files} / {report.profile.total_files}`",
                "",
            ]
        )
        self._append_mining_strategy(lines, report)
        self._append_tool_results(lines, report)
        self._append_sca_section(lines, report)
        self._append_mining_summary(lines, report)

        self._append_findings_by_severity(lines, report.findings, verification_by_finding)

        lines.extend(["## 验证证据", ""])
        if not report.verification_results:
            lines.append("暂无验证尝试。")
        for verification in report.verification_results:
            self._append_verification(lines, verification)

        self._append_artifact_index(lines, report)
        self._append_fix_summary(lines, report.findings)
        return "\n".join(lines).rstrip() + "\n"

    def _append_executive_summary(
        self,
        lines: list[str],
        report: AuditReport,
        verification_by_finding: dict[str, VerificationResult],
    ) -> None:
        score = self._security_score(report.findings, verification_by_finding)
        verdict = "通过" if score >= 80 else "未通过"
        severity_counts = self._severity_counts(report.findings)
        verified_counts = self._verified_counts(report.findings, verification_by_finding)
        poc_count = sum(
            1
            for finding in report.findings
            if self._has_reportable_poc(finding, verification_by_finding.get(finding.id))
        )
        lines.extend(
            [
                "## 执行摘要",
                "",
                f"**安全评分: {score}/100** [{verdict}]",
                "",
                "### 漏洞发现概览",
                "",
                "| 严重程度 | 数量 | 已验证/复现 |",
                "|----------|-------|----------|",
            ]
        )
        for severity in ["critical", "high", "medium", "low", "unknown"]:
            count = severity_counts.get(severity, 0)
            if count or severity != "unknown":
                lines.append(
                    f"| **{self._severity_label(severity)}** | {count} | {verified_counts.get(severity, 0)} |"
                )
        lines.extend(
            [
                f"| **总计** | {len(report.findings)} | {sum(verified_counts.values())} |",
                "",
                "### 审计指标",
                "",
                f"- **分析文件数:** {report.profile.scanned_files} / {report.profile.total_files}",
                f"- **工具调用次数:** {len(report.tool_results)}",
                f"- **候选漏洞:** {len(report.candidates)}",
                f"- **最终漏洞:** {len(report.findings)}",
                f"- **验证尝试:** {len(report.verification_results)}",
                f"- **生成的 PoC:** {poc_count}",
                "",
            ]
        )

    def _append_findings_by_severity(
        self,
        lines: list[str],
        findings: list[Finding],
        verification_by_finding: dict[str, VerificationResult],
    ) -> None:
        if not findings:
            lines.extend(["## 漏洞详情", "", "未发现可进入报告的漏洞。", ""])
            return
        grouped: dict[str, list[Finding]] = {key: [] for key in ["critical", "high", "medium", "low", "unknown"]}
        for finding in findings:
            grouped.setdefault(self._severity_key(finding.severity), []).append(finding)
        for severity in ["critical", "high", "medium", "low", "unknown"]:
            severity_findings = grouped.get(severity, [])
            if not severity_findings:
                continue
            lines.extend([f"## {self._severity_label(severity)} 漏洞", ""])
            for index, finding in enumerate(severity_findings, start=1):
                display_id = f"{severity.upper()}-{index}" if severity != "unknown" else f"UNKNOWN-{index}"
                self._append_finding(lines, finding, verification_by_finding.get(finding.id), display_id)

    def _format_dict(self, value: dict[str, Any]) -> str:
        if not value:
            return "unknown"
        return ", ".join(f"{key}: {val}" for key, val in value.items())

    def _severity_key(self, value: str) -> str:
        severity = (value or "unknown").lower()
        if severity in {"critical", "high", "medium", "low"}:
            return severity
        return "unknown"

    def _severity_label(self, severity: str) -> str:
        labels = {
            "critical": "严重 (Critical)",
            "high": "高危 (High)",
            "medium": "中危 (Medium)",
            "low": "低危 (Low)",
            "unknown": "未知 (Unknown)",
        }
        return labels.get(severity, labels["unknown"])

    def _severity_counts(self, findings: list[Finding]) -> dict[str, int]:
        counts = {key: 0 for key in ["critical", "high", "medium", "low", "unknown"]}
        for finding in findings:
            counts[self._severity_key(finding.severity)] += 1
        return counts

    def _verified_counts(
        self,
        findings: list[Finding],
        verification_by_finding: dict[str, VerificationResult],
    ) -> dict[str, int]:
        counts = {key: 0 for key in ["critical", "high", "medium", "low", "unknown"]}
        for finding in findings:
            verification = verification_by_finding.get(finding.id)
            if verification and self._has_verification_evidence(verification):
                counts[self._severity_key(finding.severity)] += 1
        return counts

    def _security_score(
        self,
        findings: list[Finding],
        verification_by_finding: dict[str, VerificationResult],
    ) -> int:
        penalty_by_severity = {"critical": 35, "high": 25, "medium": 12, "low": 5, "unknown": 8}
        score = 100
        for finding in findings:
            penalty = penalty_by_severity[self._severity_key(finding.severity)]
            verification = verification_by_finding.get(finding.id)
            if verification and self._has_verification_evidence(verification):
                penalty += 5
            score -= penalty
        return max(0, min(100, score))

    def _has_verification_evidence(self, verification: VerificationResult) -> bool:
        return verification.status in {"verified", "harness_reproduced", "partial_dynamic_proof", "partially_verified"}

    def _status_badges(self, finding: Finding, verification: VerificationResult | None) -> str:
        status = verification.status if verification else finding.verification_status
        status_labels = {
            "verified": "已验证",
            "harness_reproduced": "Harness 复现",
            "partial_dynamic_proof": "局部 proof",
            "partially_verified": "部分验证",
            "blocked": "验证阻塞",
            "rejected": "已拒绝",
            "unverified": "未验证",
            "not_verified": "未验证",
        }
        badges = [f"**[{status_labels.get(status, status or '未验证')}]**"]
        if verification and verification.validation_tags:
            labels = [str(item.get("label", "")).strip() for item in verification.validation_tags if isinstance(item, dict)]
            badges.extend(f"[{label}]" for label in labels[:4] if label)
        if self._has_reportable_poc(finding, verification):
            badges.append("[含 PoC]")
        return " ".join(badges)

    def _has_reportable_poc(self, finding: Finding, verification: VerificationResult | None) -> bool:
        if self._reportable_payloads(finding, verification):
            return True
        if not verification:
            return False
        if verification.poc_path and verification.verification_mode not in {"static_only", "static_evidence", "dependency_only"}:
            return True
        artifact_names = {
            "run_poc.sh",
            "poc_harness.c",
            "poc_harness.cpp",
            "poc_harness.py",
            "poc_harness.php",
            "poc_harness.js",
            "poc_harness.java",
            "poc_harness.go",
        }
        return any(Path(str(path)).name in artifact_names for path in verification.generated_artifacts)

    def _verification_payloads(self, finding: Finding, verification: VerificationResult | None) -> list[str]:
        payloads: list[str] = []
        if verification:
            payloads.extend(str(item) for item in verification.payloads if str(item).strip())
        payloads.extend(str(item) for item in finding.exploit_payloads if str(item).strip())
        seen: set[str] = set()
        unique: list[str] = []
        for payload in payloads:
            if payload in seen:
                continue
            seen.add(payload)
            unique.append(payload)
        return unique

    def _reportable_payloads(self, finding: Finding, verification: VerificationResult | None) -> list[str]:
        return [payload for payload in self._verification_payloads(finding, verification) if not self._is_low_information_payload(payload)]

    def _is_low_information_payload(self, payload: str) -> bool:
        text = str(payload or "").strip()
        if not text:
            return True
        lowered = text.lower()
        if lowered in {"manual-validation-payload", "manual_validation_payload"}:
            return True
        if "manual-validation-payload" in lowered:
            return True
        compact = "".join(ch for ch in text if not ch.isspace())
        if len(compact) >= 32 and len(set(compact)) <= 2:
            return True
        if len(compact) >= 32 and compact.upper().count("A") / max(len(compact), 1) > 0.85:
            return True
        if "AAAAAAAAAAAAAAAA" in compact and not any(marker in text for marker in ["source=", "sink=", "target_function=", "agentic_audit_case="]):
            return True
        return False

    def _localized_recommendation(self, finding: Finding) -> str:
        recommendation = (finding.recommendation or "").strip()
        if recommendation and self._contains_cjk(recommendation):
            return recommendation
        vuln_type = (finding.vulnerability_type or "").lower()
        sink = (finding.sink or "").lower()
        if vuln_type in {"unsafe_memory_copy", "unsafe_c_string_api", "memory_corruption", "buffer_overflow"} or sink in {
            "strcpy",
            "strcat",
            "sprintf",
            "memcpy",
        }:
            return (
                "避免继续使用不带边界检查的 C 字符串/内存操作接口。应改用带长度约束的接口，"
                "在写入目标缓冲区前校验输入长度、目标容量和终止符处理，并为该触发链路补充 ASAN/UBSAN 回归用例。"
            )
        if "command" in vuln_type or "system" in sink:
            return "避免将用户输入拼接进 shell 命令。建议改用参数数组调用、固定 allowlist，并对命令参数做严格校验和回归测试。"
        if "xss" in vuln_type:
            return "在写入 HTML/DOM 前对用户可控内容进行净化或转义；仅允许必要的白名单标签和属性，并升级到已修复版本。"
        if "path" in vuln_type:
            return "对路径参数做规范化和根目录约束，拒绝目录穿越片段，并在打开文件前校验最终路径仍位于允许目录内。"
        if recommendation:
            return "建议按该漏洞链路补充输入校验、边界检查和回归测试；原始建议为英文，已在详细证据中保留机器可读字段。"
        return "结合上下文补充输入验证、边界检查和回归测试，并确保修复后重新执行静态验证和动态验证。"

    def _contains_cjk(self, text: str) -> bool:
        return any("\u4e00" <= ch <= "\u9fff" for ch in text)

    def _append_poc_section(
        self,
        lines: list[str],
        finding: Finding,
        verification: VerificationResult | None,
    ) -> None:
        poc_code = self._poc_code(finding, verification)
        payloads = self._reportable_payloads(finding, verification)
        if not poc_code and not payloads and not verification:
            return
        lines.extend(["", "**概念验证 (PoC):**", ""])
        lines.extend([f"*{self._poc_description(finding, verification)}*", ""])
        lines.extend(["**复现步骤:**", ""])
        for index, step in enumerate(self._poc_steps(finding, verification, bool(poc_code)), start=1):
            lines.append(f"{index}. {step}")
        if poc_code:
            language = "bash" if self._poc_code_is_shell(poc_code) else ""
            lines.extend(["", "**PoC 代码:**", "", f"```{language}".rstrip(), poc_code.rstrip(), "```"])
        elif payloads:
            command = self._payload_command(finding, verification)
            if command:
                lines.extend(["", "**PoC 代码:**", "", "```bash", command.rstrip(), "```"])

    def _poc_description(self, finding: Finding, verification: VerificationResult | None) -> str:
        source = finding.source or self._recipe_value(verification, "source") or "可控输入"
        sink = finding.sink or self._recipe_value(verification, "sink") or "危险操作"
        target = finding.function_name or self._recipe_value(verification, "target_function") or "目标函数"
        if not verification:
            return f"通过构造本地输入，使 {source} 进入 {target} 并到达 {sink}，用于复核静态分析给出的触发链路。"
        if verification.status == "verified":
            return f"通过真实 Runtime/CLI 执行验证输入，观察到命中预期 oracle，证明 {source} 到 {sink} 的链路可在目标程序中触发。"
        if verification.status == "harness_reproduced":
            return f"通过验证阶段生成的本地 harness 复现 {source} 到 {sink} 的关键链路，并用 checker/oracle 判断触发结果。"
        if verification.status == "partial_dynamic_proof":
            return (
                f"完整项目构建或运行受阻后，系统在无网络 sandbox 中执行局部 harness/micro proof，"
                f"验证 {source} 进入 {target} 并到达 {sink} 的局部触发模式；该证据不等同于完整目标程序已验证。"
            )
        if verification.status == "blocked":
            return f"动态验证当前被阻塞，PoC 仅用于说明应如何在满足环境依赖后复现 {source} 到 {sink} 的链路。"
        return f"通过本地验证输入和 checker 证据复核 {source} 到 {sink} 的触发链路。"

    def _poc_steps(self, finding: Finding, verification: VerificationResult | None, has_poc_code: bool) -> list[str]:
        oracle = self._oracle_label(verification)
        steps = [
            "在授权的本地隔离环境或项目 sandbox 中准备报告生成的 PoC artifact。",
        ]
        if has_poc_code:
            steps.append("执行下方 PoC 代码/命令；如果包含 `run_poc.sh`，优先在 PoC 目录中运行 `sh run_poc.sh`。")
        else:
            steps.append("将下方输入内容喂给对应 CLI、解析函数或验证阶段生成的局部 harness。")
        if finding.source or finding.sink:
            steps.append(f"确认输入从 `{finding.source or 'unknown'}` 进入目标链路，并到达 `{finding.sink or 'unknown'}`。")
        steps.append(f"观察 `{oracle}`、stdout/stderr、退出码或 sanitizer 输出，并与报告“验证证据”中的执行记录对照。")
        if verification and verification.status == "partial_dynamic_proof":
            steps.append("将结果标记为局部动态证明；除非真实目标 Runtime/CLI 也命中 oracle，否则不得升级为 verified。")
        return steps

    def _oracle_label(self, verification: VerificationResult | None) -> str:
        if not verification:
            return "预期异常信号"
        return verification.oracle or str(verification.checker_details.get("oracle", "") or "") or "预期 checker/oracle 信号"

    def _localized_verification_summary(self, verification: VerificationResult) -> str:
        raw = (verification.reproduction or verification.checker_summary or "").strip()
        if raw and self._contains_cjk(raw):
            return raw
        status = verification.status
        if status == "verified":
            return "真实 Runtime/CLI 已执行并命中预期 oracle。"
        if status == "harness_reproduced":
            return "验证阶段生成的 harness 已执行并复现关键触发链路。"
        if status == "partial_dynamic_proof":
            return "完整运行受阻后已执行局部动态证明；该证据只能证明局部链路，不能等同于完整程序 verified。"
        if status == "blocked":
            reason = verification.blocked_reason or str(verification.checker_details.get("blocked_reason", "") or "环境或预算限制")
            return f"动态验证被阻塞，原因：{reason}。"
        if status == "partially_verified":
            return "静态链路或部分动态证据成立，但仍缺少完整 Runtime/CLI 复现。"
        return raw or "暂无明确复现结论。"

    def _recipe_value(self, verification: VerificationResult | None, key: str) -> str:
        if not verification:
            return ""
        recipe = verification.verification_recipe if isinstance(verification.verification_recipe, dict) else {}
        return str(recipe.get(key) or "")

    def _poc_code(self, finding: Finding, verification: VerificationResult | None) -> str:
        if not verification:
            return self._payload_command(finding, None)
        run_script = self._read_generated_artifact(verification, {"run_poc.sh"})
        if run_script:
            return run_script
        harness = self._read_first_generated_artifact(verification, {"poc_harness.c", "poc_harness.cpp", "poc_harness.py", "poc_harness.sh"})
        if harness:
            return harness
        command = self._command_from_verification(verification)
        if command:
            return command
        return self._payload_command(finding, verification)

    def _payload_command(self, finding: Finding, verification: VerificationResult | None) -> str:
        payloads = self._reportable_payloads(finding, verification)
        if not payloads:
            payloads = [self._structured_placeholder_input(finding)]
        payload = payloads[0]
        if finding.source == "stdin" or "stdin" in finding.trigger_conditions:
            return "cat > poc_input.txt <<'EOF'\n" + payload.rstrip() + "\nEOF\n# 将 poc_input.txt 输入给目标 CLI 或局部 harness。"
        return "# 将以下输入作为目标参数、配置项或请求字段使用：\n" + payload

    def _structured_placeholder_input(self, finding: Finding) -> str:
        return "\n".join(
            [
                f"agentic_audit_case={finding.id}",
                f"target_function={finding.function_name or 'unknown'}",
                f"source={finding.source or 'unknown'}",
                f"sink={finding.sink or 'unknown'}",
                "payload=<根据目标协议填写触发字段>",
            ]
        )

    def _command_from_verification(self, verification: VerificationResult) -> str:
        command = verification.target_command or verification.sandbox_command
        if command:
            return " ".join(command)
        execution_command = verification.execution.get("command") if isinstance(verification.execution, dict) else None
        if isinstance(execution_command, list):
            return " ".join(str(item) for item in execution_command)
        if isinstance(execution_command, str):
            return execution_command
        return ""

    def _read_generated_artifact(self, verification: VerificationResult, names: set[str]) -> str:
        path = self._find_generated_artifact(verification, names)
        if not path:
            return ""
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""
        return text[:6000]

    def _read_first_generated_artifact(self, verification: VerificationResult, names: set[str]) -> str:
        return self._read_generated_artifact(verification, names)

    def _find_generated_artifact(self, verification: VerificationResult, names: set[str]) -> Path | None:
        for raw_path in verification.generated_artifacts:
            path = Path(raw_path)
            if path.name in names and path.exists() and path.is_file():
                return path
        return None

    def _poc_code_is_shell(self, code: str) -> bool:
        stripped = code.lstrip()
        return stripped.startswith("#!/") or "run_poc.sh" in stripped or "set -e" in stripped or stripped.startswith("cat >")

    def _append_evidence_chain(
        self,
        lines: list[str],
        finding: Finding,
        verification: VerificationResult | None,
    ) -> None:
        completeness, missing = self._evidence_completeness(finding, verification)
        suffix = "完整" if completeness == 5 else f"证据不完整 (缺少：{', '.join(missing)})"
        lines.extend(["", "**证据链:**", "", f"**证据链完整度**：{completeness}/5 {suffix}", ""])
        lines.extend(["#### 1) 源位置", ""])
        location = f"{finding.file_path}:{finding.line_start or ''}".rstrip(":")
        lines.append(f"- `{location}`")
        if finding.code_snippet:
            lines.extend(["```", finding.code_snippet, "```"])
        lines.extend(["", "#### 2) 调用路径", ""])
        if finding.exploit_chain:
            lines.append("`" + " -> ".join(finding.exploit_chain) + "`")
        elif finding.call_chain:
            lines.append("`" + " -> ".join(finding.call_chain) + "`")
        else:
            lines.append("_未提供调用路径_")
        lines.extend(["", "#### 3) 污点流", ""])
        if finding.source or finding.sink:
            lines.append(f"`{finding.source or 'unknown'} -> {finding.sink or 'unknown'}`")
        elif finding.evidence:
            lines.append(finding.evidence[0])
        else:
            lines.append("_未提供结构化污点流_")
        lines.extend(["", "#### 4) 验证", ""])
        if verification:
            lines.append(f"- 状态: `{verification.status}`")
            if verification.proof_level and verification.proof_level != "none":
                lines.append(f"- 证明级别: `{verification.proof_level}`")
            if verification.reproduction or verification.checker_summary:
                lines.append(f"- 结论: {self._localized_verification_summary(verification)}")
            if verification.evidence:
                lines.extend(f"- {item}" for item in verification.evidence[:5])
        else:
            lines.append("_未验证 / 未提供验证证据_")
        lines.extend(["", "#### 5) 参考", ""])
        if finding.cwe:
            lines.append(f"- CWE: `{finding.cwe}`")
        if finding.owasp:
            lines.append(f"- OWASP: `{finding.owasp}`")
        if not finding.cwe and not finding.owasp:
            lines.append("- 暂无外部编号。")
        lines.append("")

    def _evidence_completeness(
        self,
        finding: Finding,
        verification: VerificationResult | None,
    ) -> tuple[int, list[str]]:
        checks = {
            "source": bool(finding.file_path and finding.line_start),
            "call_path": bool(finding.exploit_chain or finding.call_chain or finding.chain_graph.nodes),
            "taint_flow": bool(finding.source or finding.sink or finding.evidence),
            "verification": bool(verification and self._has_verification_evidence(verification)),
            "reference": bool(finding.cwe or finding.owasp),
        }
        missing = [name for name, ok in checks.items() if not ok]
        return sum(1 for ok in checks.values() if ok), missing

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

    def _append_mining_strategy(self, lines: list[str], report: AuditReport) -> None:
        strategy = report.mining_strategy or {}
        if not strategy:
            return
        tool_names = [
            f"{item.get('name')}@p{item.get('priority', 1)}"
            for item in strategy.get("tool_selections", [])
            if isinstance(item, dict) and item.get("name")
        ]
        lines.extend(
            [
                "## MiningDirector 策略",
                "",
                f"- 校验状态: `{strategy.get('validated', False)}`",
                f"- 工具优先级: `{', '.join(tool_names) or 'none'}`",
                f"- 关注目录: `{', '.join(strategy.get('focus_directories', [])) or 'none'}`",
                f"- 优先函数: `{', '.join(strategy.get('priority_functions', [])) or 'none'}`",
                f"- Parser 入口: `{', '.join(strategy.get('parser_entries', [])) or 'none'}`",
                f"- 动态验证优先函数: `{', '.join(strategy.get('dynamic_priority_functions', [])) or 'none'}`",
                f"- 策略说明: {str(strategy.get('rationale', 'n/a'))[:500]}",
                "",
            ]
        )
        rejected = strategy.get("rejected_strategy_items", [])
        if rejected:
            lines.extend(["### 被拒绝的策略项", ""])
            for item in rejected[:20]:
                if isinstance(item, dict):
                    lines.append(f"- `{item.get('kind', 'item')}` `{item.get('value', '')}`: {item.get('reason', '')}")
            lines.append("")
        effects = strategy.get("strategy_effects", {})
        if isinstance(effects, dict) and effects:
            self._append_json_section(lines, "策略影响", effects)

    def _append_tool_results(self, lines: list[str], report: AuditReport) -> None:
        lines.extend(["## 工具执行", ""])
        if not report.tool_results:
            lines.append("- 未执行外部工具。")
        for result in report.tool_results:
            command = " ".join(result.command) if result.command else "n/a"
            artifacts = ", ".join(
                ref for ref in [result.stdout_artifact_id, result.stderr_artifact_id, result.parsed_artifact_id] if ref
            )
            lines.append(
                f"- `{result.tool}`: **{result.status}**; exit=`{result.exit_code}`; "
                f"cache_hit=`{result.cache_hit}`; command=`{command}`; "
                f"artifacts=`{artifacts or 'none'}`; {result.summary}"
            )
        lines.append("")

    def _append_sca_section(self, lines: list[str], report: AuditReport) -> None:
        dep_findings = [f for f in report.findings if f.vulnerability_type == "dependency_vulnerability"]
        if not dep_findings:
            lines.extend(["## 软件成分分析 (SCA)", "", "未发现已知依赖漏洞。", ""])
            return

        lines.extend(["## 软件成分分析 (SCA)", ""])

        severity_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        scanners: set[str] = set()
        for f in dep_findings:
            sev = f.severity.upper()
            severity_counts[sev if sev in severity_counts else "UNKNOWN"] += 1
            scanners.add(f.tool)

        lines.extend([
            "### 依赖漏洞概览",
            "",
            "| 严重程度 | 数量 |",
            "|----------|------|",
        ])
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
            if severity_counts.get(sev, 0) > 0:
                lines.append(f"| **{sev}** | {severity_counts[sev]} |")
        lines.append(f"| **总计** | {len(dep_findings)} |")
        lines.append("")
        lines.append(f"**涉及扫描器:** {', '.join(sorted(scanners))}")
        lines.append("")

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            items = [f for f in dep_findings if f.severity.upper() == sev]
            if not items:
                continue
            lines.extend([f"### {sev} 级别依赖漏洞", ""])
            for idx, f in enumerate(items[:30], 1):
                pkg = f.sink or f.file_path or "unknown"
                vuln_id = f.cwe or ""
                lines.append(
                    f"- **{pkg}** `{f.id}` `{vuln_id}` — {f.description[:200]} "
                    f"(来源: {f.tool}, 置信度: {int(f.confidence * 100)}%)"
                )
            lines.append("")

    def _append_mining_summary(self, lines: list[str], report: AuditReport) -> None:
        lines.extend(
            [
                "## 挖掘流水线",
                "",
                f"- 危险函数定位: `{len(report.dangerous_functions)}`",
                f"- 切片分析: `{len(report.program_slices)}`",
                f"- 候选漏洞生成: `{len(report.candidates)}`",
                f"- 聚合候选: `{len(getattr(report, 'aggregated_candidates', []) or [])}`",
                f"- 最终 finding: `{len(report.findings)}`",
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

    def _append_finding(
        self,
        lines: list[str],
        finding: Finding,
        verification: VerificationResult | None,
        display_id: str,
    ) -> None:
        location = f"{finding.file_path}:{finding.line_start or ''}".rstrip(":")
        lines.extend(
            [
                f"### {display_id}: {finding.title}",
                "",
                f"{self._status_badges(finding, verification)} | 类型: `{finding.vulnerability_type}`",
                "",
                f"**位置:** `{location}`",
                "",
                f"**AI 置信度:** {int(finding.confidence * 100)}%",
                "",
                f"**Finding ID:** `{finding.id}`",
                "",
                "**漏洞描述:**",
                "",
                finding.chinese_summary or finding.description or "无摘要。",
            ]
        )
        if finding.trigger_conditions:
            lines.extend(["", "#### 触发条件", ""])
            lines.extend(f"- {condition}" for condition in finding.trigger_conditions)
        if finding.code_snippet:
            lines.extend(["", "**漏洞代码:**", "", "```", finding.code_snippet, "```"])
        lines.extend(
            [
                "",
                "**修复建议:**",
                "",
                self._localized_recommendation(finding),
            ]
        )
        self._append_poc_section(lines, finding, verification)
        if finding.exploit_chain or finding.chain_graph.nodes:
            lines.extend(["", "**触发链路:**", ""])
            if finding.exploit_chain:
                lines.append("`" + " -> ".join(finding.exploit_chain) + "`")
            if finding.chain_graph.nodes:
                lines.extend(["", "```mermaid", self._chain_mermaid(finding), "```"])
        self._append_evidence_chain(lines, finding, verification)
        if finding.evidence:
            lines.extend(["#### 静态证据", ""])
            lines.extend(f"- {evidence}" for evidence in finding.evidence)
            lines.append("")
        lines.extend(["---", ""])

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
                f"- 是否执行动态验证: `{verification.dynamic_attempted}`",
                f"- 阻塞原因: `{verification.blocked_reason or 'none'}`",
                f"- 本地 fallback: `{verification.local_fallback}`",
                f"- 验证模式: `{verification.verification_mode or 'n/a'}`",
                f"- Oracle: {verification.oracle or 'n/a'}",
                f"- 目标命令: `{command}`",
                f"- 沙箱命令: `{sandbox_command}`",
                f"- PoC: `{verification.poc_path or 'n/a'}`",
                f"- 复现结论: {self._localized_verification_summary(verification)}",
                f"- evidence_artifact_ids: `{', '.join(verification.evidence_artifact_ids) or 'none'}`",
                f"- exploit_artifact_ids: `{', '.join(verification.exploit_artifact_ids) or 'none'}`",
                "",
            ]
        )
        self._append_list(lines, "环境缺口", verification.environment_gaps)
        self._append_json_section(lines, "静态验证", verification.static_verification)
        self._append_json_section(lines, "动态验证计划", verification.dynamic_verification)
        self._append_json_section(lines, "验证计划", verification.verification_plan)
        self._append_json_section(lines, "环境画像", verification.environment)
        self._append_json_section(lines, "执行记录", verification.execution)
        self._append_json_section(lines, "Checker 判定", verification.checker_verdict or verification.checker_details)
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
            lines.append(f"- `{finding.id}` {self._localized_recommendation(finding)}")

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
