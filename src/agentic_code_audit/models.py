from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ProjectProfile:
    root: str
    languages: dict[str, int] = field(default_factory=dict)
    frameworks: list[str] = field(default_factory=list)
    package_files: list[str] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)
    high_risk_files: list[str] = field(default_factory=list)
    total_files: int = 0
    scanned_files: int = 0


@dataclass
class ToolResult:
    tool: str
    status: str
    command: list[str] = field(default_factory=list)
    summary: str = ""
    raw: Any = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    started_at: str = field(default_factory=utc_now)
    finished_at: str | None = None


@dataclass
class Finding:
    id: str
    vulnerability_type: str
    severity: str
    title: str
    description: str
    file_path: str
    line_start: int | None = None
    line_end: int | None = None
    code_snippet: str = ""
    source: str = ""
    sink: str = ""
    call_chain: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    confidence: float = 0.5
    needs_verification: bool = True
    tool: str = "builtin"
    recommendation: str = ""


@dataclass
class VerificationResult:
    finding_id: str
    status: str
    method: str
    evidence: list[str] = field(default_factory=list)
    reproduction: str = ""


@dataclass
class AuditReport:
    target: str
    created_at: str
    profile: ProjectProfile
    tool_results: list[ToolResult]
    findings: list[Finding]
    verification_results: list[VerificationResult]
    llm_enabled: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def normalize_path(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve())).replace("\\", "/")
    except ValueError:
        return str(path)
