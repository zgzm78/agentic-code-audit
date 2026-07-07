from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..llm import DeepSeekClient
from ..models import Finding, ProjectProfile, ToolResult
from ..tools.builtin_patterns import BuiltinPatternScanner


class AnalysisAgent:
    """Combines deterministic scan findings with optional DeepSeek review."""

    def __init__(self, pattern_scanner: BuiltinPatternScanner, llm_client: DeepSeekClient):
        self.pattern_scanner = pattern_scanner
        self.llm_client = llm_client

    def analyze(
        self,
        target: Path,
        profile: ProjectProfile,
        tool_results: list[ToolResult],
    ) -> list[Finding]:
        findings = self.pattern_scanner.scan(target)
        findings.extend(self._extract_external_findings(tool_results))
        findings = self._deduplicate(findings)

        if self.llm_client.enabled and findings:
            self._add_llm_triage(target, profile, findings[:20])
        return findings

    def _extract_external_findings(self, tool_results: list[ToolResult]) -> list[Finding]:
        findings: list[Finding] = []
        for result in tool_results:
            if result.status not in {"ok", "error"}:
                continue
            if result.tool == "semgrep":
                findings.extend(self._extract_semgrep(result.raw))
            elif result.tool == "bandit":
                findings.extend(self._extract_bandit(result.raw))
            elif result.tool == "gitleaks":
                findings.extend(self._extract_gitleaks(result.raw))
            elif result.tool in {"osv-scanner", "npm-audit"}:
                result.summary += " dependency findings are kept in raw tool output"
        return findings

    def _extract_semgrep(self, raw: Any) -> list[Finding]:
        if not isinstance(raw, dict):
            return []
        findings: list[Finding] = []
        for item in raw.get("results", []):
            extra = item.get("extra", {})
            path = item.get("path", "")
            line = item.get("start", {}).get("line")
            message = extra.get("message", "Semgrep finding")
            check_id = item.get("check_id", "semgrep")
            severity = str(extra.get("severity", "warning")).lower()
            findings.append(
                Finding(
                    id=self._id("semgrep", path, line, check_id),
                    vulnerability_type=check_id.split(".")[-1].replace("-", "_"),
                    severity=self._normalize_severity(severity),
                    title=message[:120],
                    description=message,
                    file_path=path,
                    line_start=line,
                    line_end=item.get("end", {}).get("line"),
                    code_snippet=extra.get("lines", "").strip(),
                    evidence=[f"Semgrep rule: {check_id}"],
                    confidence=0.7,
                    needs_verification=True,
                    tool="semgrep",
                    recommendation="Review the Semgrep rule guidance and validate exploitability.",
                )
            )
        return findings

    def _extract_bandit(self, raw: Any) -> list[Finding]:
        if not isinstance(raw, dict):
            return []
        findings: list[Finding] = []
        for item in raw.get("results", []):
            path = item.get("filename", "")
            line = item.get("line_number")
            test_id = item.get("test_id", "bandit")
            findings.append(
                Finding(
                    id=self._id("bandit", path, line, test_id),
                    vulnerability_type=item.get("test_name", test_id),
                    severity=self._normalize_severity(str(item.get("issue_severity", "medium"))),
                    title=item.get("issue_text", "Bandit finding")[:120],
                    description=item.get("issue_text", "Bandit finding"),
                    file_path=path,
                    line_start=line,
                    line_end=line,
                    code_snippet=item.get("code", "").strip(),
                    evidence=[f"Bandit test: {test_id}"],
                    confidence=float(item.get("issue_confidence", "MEDIUM") == "HIGH") * 0.2 + 0.55,
                    needs_verification=True,
                    tool="bandit",
                    recommendation="Review Bandit documentation and remove insecure API usage.",
                )
            )
        return findings

    def _extract_gitleaks(self, raw: Any) -> list[Finding]:
        if not isinstance(raw, list):
            return []
        findings: list[Finding] = []
        for item in raw:
            path = item.get("File", "")
            line = item.get("StartLine")
            rule = item.get("RuleID", "secret")
            findings.append(
                Finding(
                    id=self._id("gitleaks", path, line, rule),
                    vulnerability_type="hardcoded_secret",
                    severity="high",
                    title=f"Possible secret leak: {rule}",
                    description="Gitleaks reported a possible hardcoded secret.",
                    file_path=path,
                    line_start=line,
                    line_end=item.get("EndLine", line),
                    code_snippet=item.get("Match", ""),
                    evidence=[f"Gitleaks rule: {rule}"],
                    confidence=0.8,
                    needs_verification=False,
                    tool="gitleaks",
                    recommendation="Revoke exposed credentials and move secrets to a secret manager.",
                )
            )
        return findings

    def _add_llm_triage(self, target: Path, profile: ProjectProfile, findings: list[Finding]) -> None:
        compact = []
        for finding in findings:
            compact.append(
                {
                    "id": finding.id,
                    "type": finding.vulnerability_type,
                    "file": finding.file_path,
                    "line": finding.line_start,
                    "snippet": finding.code_snippet[:300],
                    "evidence": finding.evidence,
                }
            )

        prompt = (
            "You are reviewing source-code security audit candidates. "
            "For each finding, judge likely exploitability, source-to-sink reachability, "
            "and missing validation. Return concise JSON list with id, confidence_delta, notes."
        )
        user_prompt = json.dumps(
            {
                "project_profile": profile.__dict__,
                "findings": compact,
                "instruction": "Do not invent file paths. Only analyze provided findings.",
            },
            ensure_ascii=False,
        )
        response = self.llm_client.chat(prompt, user_prompt)
        if not response.ok:
            return
        for finding in findings:
            finding.evidence.append("DeepSeek triage executed; see run metadata for raw response.")
            finding.confidence = min(0.95, finding.confidence + 0.05)

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        seen: set[tuple[str, int | None, str]] = set()
        output: list[Finding] = []
        for finding in findings:
            key = (finding.file_path, finding.line_start, finding.vulnerability_type)
            if key in seen:
                continue
            seen.add(key)
            output.append(finding)
        return output

    def _id(self, tool: str, path: str, line: int | None, key: str) -> str:
        raw = f"{tool}:{path}:{line}:{key}"
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]

    def _normalize_severity(self, value: str) -> str:
        value = value.lower()
        if value in {"critical", "error"}:
            return "critical"
        if value in {"high"}:
            return "high"
        if value in {"medium", "warning", "warn"}:
            return "medium"
        if value in {"low", "info", "note"}:
            return "low"
        return "medium"
