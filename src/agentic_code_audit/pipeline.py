from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .agents.analysis import AnalysisAgent
from .agents.profiler import ProjectProfiler
from .agents.verification import VerificationAgent
from .config import Settings
from .llm import DeepSeekClient
from .models import AuditReport, utc_now
from .reporting import ReportWriter
from .tools.builtin_patterns import BuiltinPatternScanner
from .tools.runner import SecurityToolRunner


@dataclass
class AuditArtifacts:
    report: AuditReport
    json_path: Path
    markdown_path: Path


class AuditPipeline:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.profiler = ProjectProfiler(settings)
        self.tool_runner = SecurityToolRunner(settings)
        self.llm_client = DeepSeekClient(settings)
        self.analysis_agent = AnalysisAgent(BuiltinPatternScanner(settings), self.llm_client)
        self.verification_agent = VerificationAgent()
        self.report_writer = ReportWriter()

    def run(self, target: Path, output_dir: Path) -> AuditArtifacts:
        target = target.resolve()
        profile = self.profiler.profile(target)
        tool_results = self.tool_runner.run_all(target)
        findings = self.analysis_agent.analyze(target, profile, tool_results)
        verification = self.verification_agent.verify(target, findings)
        report = AuditReport(
            target=str(target),
            created_at=utc_now(),
            profile=profile,
            tool_results=tool_results,
            findings=findings,
            verification_results=verification,
            llm_enabled=self.llm_client.enabled,
        )
        json_path, markdown_path = self.report_writer.write(report, output_dir)
        return AuditArtifacts(report=report, json_path=json_path, markdown_path=markdown_path)
