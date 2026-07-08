from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from ..config import Settings
from ..inputs import TargetResolver
from ..llm import DeepSeekClient
from ..models import AgentEvent, AuditReport, utc_now
from ..tools.runner import SecurityToolRunner
from .mining import (
    CandidateGenerator,
    ClueAggregator,
    DangerousFunctionLocator,
    SliceAnalyzer,
    VulnerabilityClassifier,
)
from .recon import ReconAgent
from .semantic import SemanticAgent
from .verification import VerificationAgent


class OrchestratorAgent:
    """Coordinates the source audit workflow as explicit multi-agent stages."""

    def __init__(
        self,
        settings: Settings,
        app_root: Path,
        event_sink: Callable[[str, str, str, dict[str, Any]], None] | None = None,
    ):
        self.settings = settings
        self.app_root = app_root.resolve()
        self.event_sink = event_sink
        self.resolver = TargetResolver(self.app_root / "runs")
        self.recon_agent = ReconAgent(settings)
        self.semantic_agent = SemanticAgent(settings)
        self.tool_runner = SecurityToolRunner(settings, event_sink=event_sink)
        self.llm_client = DeepSeekClient(settings)
        self.dangerous_locator = DangerousFunctionLocator()
        self.slice_analyzer = SliceAnalyzer()
        self.candidate_generator = CandidateGenerator()
        self.clue_aggregator = ClueAggregator()
        self.vulnerability_classifier = VulnerabilityClassifier()
        self.verification_agent = VerificationAgent(
            auto_build_native=settings.auto_build_native,
            llm_client=self.llm_client,
            event_sink=event_sink,
        )

    def run(self, target_ref: str, output_dir: Path, runtime_url: str = "") -> AuditReport:
        if not self.llm_client.enabled:
            raise ValueError("DEEPSEEK_API_KEY is required. DeepSeek is mandatory for agentic audit tasks.")
        events: list[AgentEvent] = []

        self._emit("InputAgent", "stage_start", "解析目标并准备工作区", {"target": target_ref})
        input_event = AgentEvent(agent="InputAgent", action="resolve_target", status="running")
        input_source = self.resolver.resolve(target_ref)
        input_event.status = "completed"
        input_event.detail = (
            f"kind={input_source.kind}; local_path={input_source.local_path}; commit={input_source.commit}"
        )
        input_event.finished_at = utc_now()
        events.append(input_event)
        self._emit("InputAgent", "stage_done", "目标解析完成", input_event.__dict__)

        target = Path(input_source.local_path)
        self._emit("ReconAgent", "stage_start", "项目画像分析开始", {"path": str(target)})
        profile, event = self.recon_agent.run(target)
        events.append(event)
        self._emit("ReconAgent", "stage_done", "项目画像分析完成", event.__dict__)

        self._emit("SemanticAgent", "stage_start", "轻量语义索引构建开始", {"path": str(target)})
        semantic_index, event = self.semantic_agent.run(target)
        events.append(event)
        self._emit("SemanticAgent", "stage_done", "轻量语义索引构建完成", event.__dict__)

        self._emit("ToolAgent", "stage_start", "外部安全工具扫描开始", {"path": str(target)})
        tool_event = AgentEvent(agent="ToolAgent", action="run_security_tools", status="running")
        tool_results = self.tool_runner.run_all(target)
        tool_event.status = "completed"
        tool_event.detail = "; ".join(f"{result.tool}:{result.status}" for result in tool_results)
        tool_event.finished_at = utc_now()
        events.append(tool_event)
        self._emit("ToolAgent", "stage_done", "外部安全工具扫描完成", tool_event.__dict__)

        self._emit("DangerousFunctionLocator", "stage_start", "危险函数和危险 API 定位开始", {})
        dangerous_event = AgentEvent(agent="DangerousFunctionLocator", action="locate_dangerous_functions", status="running")
        dangerous_functions = self.dangerous_locator.locate(target, tool_results)
        dangerous_event.status = "completed"
        dangerous_event.detail = f"dangerous_functions={len(dangerous_functions)}"
        dangerous_event.finished_at = utc_now()
        events.append(dangerous_event)
        self._emit("DangerousFunctionLocator", "stage_done", "危险函数和危险 API 定位完成", dangerous_event.__dict__)

        self._emit("SliceAnalyzer", "stage_start", "程序切片分析开始", {"dangerous_functions": len(dangerous_functions)})
        slice_event = AgentEvent(agent="SliceAnalyzer", action="build_program_slices", status="running")
        program_slices = self.slice_analyzer.analyze(target, dangerous_functions, semantic_index, self.llm_client)
        slice_event.status = "completed"
        slice_event.detail = f"program_slices={len(program_slices)}"
        slice_event.finished_at = utc_now()
        events.append(slice_event)
        self._emit("SliceAnalyzer", "stage_done", "程序切片分析完成", slice_event.__dict__)

        self._emit("CandidateGenerator", "stage_start", "候选漏洞生成开始", {"program_slices": len(program_slices)})
        candidate_event = AgentEvent(agent="CandidateGenerator", action="generate_candidates", status="running")
        candidates = self.candidate_generator.generate(program_slices, self.llm_client)
        candidate_event.status = "completed"
        candidate_event.detail = f"candidates={len(candidates)}"
        candidate_event.finished_at = utc_now()
        events.append(candidate_event)
        self._emit("CandidateGenerator", "stage_done", "候选漏洞生成完成", candidate_event.__dict__)

        self._emit("ClueAggregator", "stage_start", "线索汇聚和去重开始", {"candidates": len(candidates)})
        aggregate_event = AgentEvent(agent="ClueAggregator", action="aggregate_clues", status="running")
        aggregated_candidates = self.clue_aggregator.aggregate(candidates)
        aggregate_event.status = "completed"
        aggregate_event.detail = f"aggregated_candidates={len(aggregated_candidates)}"
        aggregate_event.finished_at = utc_now()
        events.append(aggregate_event)
        self._emit("ClueAggregator", "stage_done", "线索汇聚和去重完成", aggregate_event.__dict__)

        self._emit("VulnerabilityClassifier", "stage_start", "漏洞类型判定开始", {"candidates": len(aggregated_candidates)})
        classify_event = AgentEvent(agent="VulnerabilityClassifier", action="classify_vulnerabilities", status="running")
        findings = self.vulnerability_classifier.classify(aggregated_candidates, program_slices, self.llm_client)
        classify_event.status = "completed"
        classify_event.detail = f"findings={len(findings)}"
        classify_event.finished_at = utc_now()
        events.append(classify_event)
        self._emit("VulnerabilityClassifier", "stage_done", "漏洞类型判定完成", classify_event.__dict__)

        self._emit("VerificationAgent", "stage_start", "漏洞验证和 PoC 生成开始", {"findings": len(findings)})
        verification_event = AgentEvent(
            agent="VerificationAgent",
            action="verify_and_generate_poc",
            status="running",
        )
        verification = self.verification_agent.verify(target, findings, output_dir, profile, runtime_url)
        verification_event.status = "completed"
        verification_event.detail = f"verification_results={len(verification)}; runtime_url={runtime_url or 'none'}"
        verification_event.finished_at = utc_now()
        events.append(verification_event)
        self._emit("VerificationAgent", "stage_done", "漏洞验证和 PoC 生成完成", verification_event.__dict__)

        return AuditReport(
            input_source=input_source,
            target=str(target),
            created_at=utc_now(),
            profile=profile,
            semantic_index=semantic_index,
            tool_results=tool_results,
            dangerous_functions=dangerous_functions,
            program_slices=program_slices,
            candidates=candidates,
            findings=findings,
            verification_results=verification,
            agent_events=events,
            llm_enabled=self.llm_client.enabled,
        )

    def _emit(self, agent: str, event_type: str, message: str, metadata: dict[str, Any]) -> None:
        if self.event_sink:
            self.event_sink(agent, event_type, message, metadata)
