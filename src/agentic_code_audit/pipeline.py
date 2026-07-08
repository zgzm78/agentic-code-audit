from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .config import Settings
from .agents.orchestrator import OrchestratorAgent
from .models import AuditReport
from .reporting import ReportWriter


@dataclass
class AuditArtifacts:
    report: AuditReport
    json_path: Path
    markdown_path: Path


class AuditPipeline:
    def __init__(
        self,
        settings: Settings,
        event_sink: Callable[[str, str, str, dict[str, Any]], None] | None = None,
    ):
        self.settings = settings
        self.app_root = Path.cwd()
        self.orchestrator = OrchestratorAgent(settings, self.app_root, event_sink=event_sink)
        self.report_writer = ReportWriter()

    def run(self, target: str | Path, output_dir: Path, runtime_url: str = "") -> AuditArtifacts:
        report = self.orchestrator.run(str(target), output_dir, runtime_url)
        json_path, markdown_path = self.report_writer.write(report, output_dir)
        return AuditArtifacts(report=report, json_path=json_path, markdown_path=markdown_path)
