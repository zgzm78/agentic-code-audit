from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from ..config import Settings
from ..models import Finding, normalize_path
from ..path_policy import PathPolicy


@dataclass(frozen=True)
class PatternRule:
    vulnerability_type: str
    severity: str
    title: str
    regex: re.Pattern[str]
    sink_hint: str
    recommendation: str


RULES = [
    PatternRule(
        vulnerability_type="sql_injection",
        severity="high",
        title="Possible SQL injection",
        regex=re.compile(
            r"(execute|query|raw|cursor\.execute)\s*\([^)]*(\+|%|format\(|f[\"'])",
            re.IGNORECASE,
        ),
        sink_hint="SQL execution",
        recommendation="Use parameterized queries or ORM-safe query builders.",
    ),
    PatternRule(
        vulnerability_type="command_injection",
        severity="critical",
        title="Possible command injection",
        regex=re.compile(
            r"(os\.(system|popen)\s*\(|subprocess\.(popen|call|run)\s*\(|\bexec\(|shell_exec\(|(?<!\.)\bsystem\(|std::system\(|(?<!\.)\bpopen\(|child_process\.(exec|spawn)\s*\()",
            re.IGNORECASE,
        ),
        sink_hint="Command execution",
        recommendation="Avoid shell execution or pass arguments as arrays with strict allowlists.",
    ),
    PatternRule(
        vulnerability_type="path_traversal",
        severity="high",
        title="Possible path traversal",
        regex=re.compile(
            r"\b(open|readfile|send_file|send_from_directory|fs\.readFile|FileInputStream)\s*\([^)]*((request|req\.|param|query|args|GET|POST)|([\"'][^\"']*[\"']\s*\+\s*[A-Za-z_])|([A-Za-z_][A-Za-z0-9_.]*\s*\+\s*[\"']))",
            re.IGNORECASE,
        ),
        sink_hint="File access",
        recommendation="Normalize paths and enforce a fixed base directory allowlist.",
    ),
    PatternRule(
        vulnerability_type="hardcoded_secret",
        severity="medium",
        title="Possible hardcoded secret",
        regex=re.compile(
            r"(api[_-]?key|secret|token|password|passwd)\s*[:=]\s*[\"'][^\"']{12,}[\"']",
            re.IGNORECASE,
        ),
        sink_hint="Secret literal",
        recommendation="Move secrets to environment variables or a secret manager.",
    ),
    PatternRule(
        vulnerability_type="unsafe_c_string_api",
        severity="medium",
        title="Possible unsafe C/C++ string API",
        regex=re.compile(r"\b(strcpy|strcat|sprintf|vsprintf|gets)\s*\(", re.IGNORECASE),
        sink_hint="Unsafe C/C++ string operation",
        recommendation="Use bounded APIs and validate destination buffer sizes.",
    ),
    PatternRule(
        vulnerability_type="unsafe_memory_copy",
        severity="medium",
        title="Possible unsafe memory copy",
        regex=re.compile(r"\b(memcpy|memmove|std::memcpy|std::memmove)\s*\(", re.IGNORECASE),
        sink_hint="Memory copy operation",
        recommendation="Validate source length, destination size, and integer arithmetic before copying.",
    ),
]


SOURCE_HINT = re.compile(r"(request|req\.|args|query|param|input|form|GET|POST)", re.IGNORECASE)


class BuiltinPatternScanner:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.path_policy = PathPolicy()

    def scan(self, root: Path) -> list[Finding]:
        root = root.resolve()
        findings: list[Finding] = []
        scanned = 0
        for path in root.rglob("*"):
            if scanned >= self.settings.max_files:
                break
            if not path.is_file() or self.path_policy.classify(normalize_path(path, root)).action == "exclude":
                continue
            try:
                if path.stat().st_size > self.settings.max_file_size:
                    continue
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            scanned += 1
            findings.extend(self._scan_file(root, path, text))
        return findings

    def _scan_file(self, root: Path, path: Path, text: str) -> list[Finding]:
        findings: list[Finding] = []
        rel = normalize_path(path, root)
        for line_no, line in enumerate(text.splitlines(), start=1):
            if self._is_comment_only(line):
                continue
            for rule in RULES:
                if not rule.regex.search(line):
                    continue
                evidence = [f"Matched builtin rule: {rule.vulnerability_type}"]
                if SOURCE_HINT.search(line):
                    evidence.append("Line contains user-input source hint.")
                finding_id = self._finding_id(rel, line_no, rule.vulnerability_type, line)
                findings.append(
                    Finding(
                        id=finding_id,
                        vulnerability_type=rule.vulnerability_type,
                        severity=rule.severity,
                        title=rule.title,
                        description=(
                            f"Builtin pattern scanner found a risky {rule.sink_hint.lower()} "
                            "operation. Manual or LLM-assisted reachability review is required."
                        ),
                        file_path=rel,
                        line_start=line_no,
                        line_end=line_no,
                        code_snippet=line.strip(),
                        source="user input" if SOURCE_HINT.search(line) else "unknown",
                        sink=rule.sink_hint,
                        evidence=evidence,
                        confidence=0.65 if SOURCE_HINT.search(line) else 0.45,
                        needs_verification=True,
                        tool="builtin-patterns",
                        recommendation=rule.recommendation,
                    )
                )
        return findings

    def _is_comment_only(self, line: str) -> bool:
        stripped = line.strip()
        return stripped.startswith(("#", "//", "/*", "*", "*/"))

    def _finding_id(self, rel: str, line_no: int, vuln_type: str, line: str) -> str:
        digest = hashlib.sha1(f"{rel}:{line_no}:{vuln_type}:{line}".encode("utf-8")).hexdigest()
        return digest[:12]
