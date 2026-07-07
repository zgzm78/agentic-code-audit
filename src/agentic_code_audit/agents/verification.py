from __future__ import annotations

from pathlib import Path

from ..models import Finding, VerificationResult


class VerificationAgent:
    """First-stage verifier: confirms evidence is anchored in real source files.

    Dynamic verification will extend this layer with container startup and HTTP/API payload checks.
    """

    def verify(self, target: Path, findings: list[Finding]) -> list[VerificationResult]:
        results: list[VerificationResult] = []
        for finding in findings:
            results.append(self._verify_static_anchor(target, finding))
        return results

    def _verify_static_anchor(self, target: Path, finding: Finding) -> VerificationResult:
        file_path = target / finding.file_path
        evidence: list[str] = []
        if not file_path.exists():
            return VerificationResult(
                finding_id=finding.id,
                status="failed",
                method="static-anchor",
                evidence=[f"File does not exist: {finding.file_path}"],
            )

        evidence.append(f"File exists: {finding.file_path}")
        if finding.line_start:
            try:
                lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                if 1 <= finding.line_start <= len(lines):
                    line = lines[finding.line_start - 1].strip()
                    evidence.append(f"Line {finding.line_start} exists.")
                    if finding.code_snippet and finding.code_snippet[:40] in line:
                        evidence.append("Reported snippet matches source line.")
                else:
                    evidence.append(f"Line {finding.line_start} is outside file range.")
            except OSError as exc:
                evidence.append(f"Could not read file: {exc}")

        status = "needs_dynamic_verification" if finding.needs_verification else "confirmed_static"
        return VerificationResult(
            finding_id=finding.id,
            status=status,
            method="static-anchor",
            evidence=evidence,
            reproduction=self._reproduction_hint(finding),
        )

    def _reproduction_hint(self, finding: Finding) -> str:
        if finding.vulnerability_type == "sql_injection":
            return "Start the application, reach the affected route, and send SQL metacharacters in the source parameter."
        if finding.vulnerability_type == "command_injection":
            return "Exercise the affected function with shell metacharacters in controlled sandbox only."
        if finding.vulnerability_type == "path_traversal":
            return "Exercise the affected file parameter with traversal payloads inside a sandboxed target."
        if finding.vulnerability_type == "hardcoded_secret":
            return "Confirm whether the literal is a real credential, then rotate it if exposed."
        return "Review the call chain and construct a minimal trigger for the reported sink."
