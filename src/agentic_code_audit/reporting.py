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
            "# Agentic Code Audit Report",
            "",
            f"- Target: `{report.target}`",
            f"- Created At: `{report.created_at}`",
            f"- LLM Enabled: `{report.llm_enabled}`",
            "",
            "## Project Profile",
            "",
            f"- Languages: `{report.profile.languages}`",
            f"- Frameworks: `{', '.join(report.profile.frameworks) or 'unknown'}`",
            f"- Package Files: `{', '.join(report.profile.package_files) or 'none'}`",
            f"- Total Files: `{report.profile.total_files}`",
            f"- Scanned Files: `{report.profile.scanned_files}`",
            "",
            "## Tool Results",
            "",
        ]
        for result in report.tool_results:
            command = " ".join(result.command) if result.command else ""
            lines.append(f"- `{result.tool}`: **{result.status}** {result.summary} `{command}`")

        lines.extend(["", "## Findings", ""])
        if not report.findings:
            lines.append("No candidate vulnerabilities were found.")
        for finding in report.findings:
            lines.extend(
                [
                    f"### {finding.id} - {finding.title}",
                    "",
                    f"- Type: `{finding.vulnerability_type}`",
                    f"- Severity: `{finding.severity}`",
                    f"- Confidence: `{finding.confidence:.2f}`",
                    f"- File: `{finding.file_path}:{finding.line_start or ''}`",
                    f"- Tool: `{finding.tool}`",
                    f"- Source: `{finding.source or 'unknown'}`",
                    f"- Sink: `{finding.sink or 'unknown'}`",
                    f"- Recommendation: {finding.recommendation or 'Review and validate.'}",
                    "",
                    "Evidence:",
                ]
            )
            for evidence in finding.evidence:
                lines.append(f"- {evidence}")
            if finding.code_snippet:
                lines.extend(["", "```", finding.code_snippet, "```", ""])

        lines.extend(["", "## Verification", ""])
        for verification in report.verification_results:
            lines.extend(
                [
                    f"### {verification.finding_id}",
                    "",
                    f"- Status: `{verification.status}`",
                    f"- Method: `{verification.method}`",
                    f"- Reproduction: {verification.reproduction}",
                    "",
                ]
            )
            for evidence in verification.evidence:
                lines.append(f"- {evidence}")
            lines.append("")
        return "\n".join(lines)
