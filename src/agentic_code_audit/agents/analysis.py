from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from ..llm import DeepSeekClient
from ..models import Finding, ProjectProfile, SemanticIndex, ToolResult
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
        semantic_index: SemanticIndex | None = None,
    ) -> list[Finding]:
        findings = self.pattern_scanner.scan(target)
        findings.extend(self._extract_external_findings(tool_results))
        findings = self._deduplicate(findings)
        if semantic_index:
            self._enrich_with_context(target, findings, semantic_index)

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

    def _enrich_with_context(
        self,
        target: Path,
        findings: list[Finding],
        semantic_index: SemanticIndex,
    ) -> None:
        routes_by_file = {}
        for route in semantic_index.routes:
            routes_by_file.setdefault(route.file_path, []).append(route)

        for finding in findings:
            file_path = target / finding.file_path
            context = self._read_context(file_path, finding.line_start or 1)
            source_name, source_expr = self._infer_source(context, finding.code_snippet)
            route = self._nearest_route(routes_by_file.get(finding.file_path, []), finding.line_start)

            if source_expr and (not finding.source or finding.source == "unknown"):
                finding.source = source_expr
            if route:
                finding.route = f"{route.method} {route.route}"
                finding.call_chain = [finding.route, route.handler, finding.sink or "security sink"]
                finding.evidence.append(f"Nearest route: {finding.route} -> {route.handler}")
            elif not finding.call_chain:
                finding.call_chain = [finding.file_path, finding.sink or "security sink"]

            if source_name:
                finding.evidence.append(f"Likely tainted variable: {source_name}")
                finding.confidence = min(0.9, finding.confidence + 0.15)

            finding.exploit_payloads = self._payloads_for(finding)
            finding.exploit_chain = self._exploit_chain_for(finding)
            finding.cwe, finding.owasp = self._taxonomy(finding.vulnerability_type)

    def _read_context(self, file_path: Path, line_start: int) -> list[tuple[int, str]]:
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return []
        start = max(1, line_start - 8)
        end = min(len(lines), line_start + 3)
        return [(idx, lines[idx - 1]) for idx in range(start, end + 1)]

    def _infer_source(self, context: list[tuple[int, str]], snippet: str) -> tuple[str, str]:
        assignments: dict[str, str] = {}
        for _, line in context:
            match = re.search(
                r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(request\.(args|form|json|values|GET|POST).*|req\.(query|body|params).*)",
                line,
            )
            if match:
                assignments[match.group(1)] = match.group(2).strip()
        for name, expr in assignments.items():
            if name in snippet or any(name in line for _, line in context[-3:]):
                return name, expr
        if re.search(r"request\.|req\.|\$_GET|\$_POST|input\(", snippet):
            return "inline_user_input", "inline request input"
        return "", ""

    def _nearest_route(self, routes: list[Any], line: int | None):
        if not routes:
            return None
        if not line:
            return routes[-1]
        before = [route for route in routes if route.line_start <= line]
        return before[-1] if before else None

    def _payloads_for(self, finding: Finding) -> list[str]:
        payloads = {
            "sql_injection": ["' OR '1'='1", "1 UNION SELECT NULL", "1; SELECT sqlite_version();--"],
            "command_injection": ["127.0.0.1; id", "127.0.0.1 && whoami", "$(id)"],
            "path_traversal": ["../../../../etc/passwd", "..\\..\\..\\Windows\\win.ini"],
            "hardcoded_secret": ["rotate-secret", "secret-scan-confirmation"],
        }
        return payloads.get(finding.vulnerability_type, ["manual-validation-payload"])

    def _exploit_chain_for(self, finding: Finding) -> list[str]:
        if finding.vulnerability_type == "hardcoded_secret":
            return [
                "secret literal exists in source code",
                "repository access exposes the credential material",
                "impact: credential disclosure or credential reuse risk",
            ]
        chain = ["attacker controls input"]
        if finding.route:
            chain.append(f"send payload to {finding.route}")
        if finding.source:
            chain.append(f"input reaches source {finding.source}")
        if finding.sink:
            chain.append(f"tainted data reaches sink {finding.sink}")
        chain.append(f"impact: {finding.vulnerability_type}")
        return chain

    def _taxonomy(self, vuln_type: str) -> tuple[str, str]:
        mapping = {
            "sql_injection": ("CWE-89", "A03:2021-Injection"),
            "command_injection": ("CWE-78", "A03:2021-Injection"),
            "path_traversal": ("CWE-22", "A01:2021-Broken Access Control"),
            "hardcoded_secret": ("CWE-798", "A07:2021-Identification and Authentication Failures"),
        }
        return mapping.get(vuln_type, ("", ""))

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
