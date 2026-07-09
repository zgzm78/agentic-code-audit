from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from ..config import Settings
from ..inputs import TargetResolver
from ..llm import DeepSeekClient
from ..models import AgentEvent, AuditReport, utc_now
from ..tools.runner import ToolPlanner, ToolRunner
from .mining import VulnerabilityMiningAgent
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
        self.tool_runner = ToolRunner(settings)
        self.tool_planner = ToolPlanner(self.tool_runner.registry, self.tool_runner.env)
        self.recon_agent = ReconAgent(settings, tool_runner=self.tool_runner, tool_planner=self.tool_planner)
        self.semantic_agent = SemanticAgent(settings)
        self.llm_client = DeepSeekClient(settings)
        self.vulnerability_mining_agent = VulnerabilityMiningAgent(
            tool_runner=self.tool_runner,
            llm_client=self.llm_client,
            event_sink=event_sink,
            tool_planner=self.tool_planner,
        )
        self.verification_agent = VerificationAgent(
            auto_build_native=settings.auto_build_native,
            llm_client=self.llm_client,
            event_sink=event_sink,
        )

    def run(self, target_ref: str, output_dir: Path, runtime_url: str = "") -> AuditReport:
        if not self.llm_client.enabled:
            raise ValueError("LLM API key is required. A configured LLM is mandatory for agentic audit tasks.")
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
        self._emit(
            "ReconAgent",
            "stage_done",
            "项目画像分析完成",
            {**event.__dict__, "profile_summary": profile.profile_summary},
        )

        self._emit("SemanticAgent", "stage_start", "轻量语义索引构建开始", {"path": str(target)})
        semantic_index, event = self.semantic_agent.run(target)
        events.append(event)
        self._emit("SemanticAgent", "stage_done", "轻量语义索引构建完成", event.__dict__)

        self._emit("VulnerabilityMiningAgent", "stage_start", "漏洞挖掘 Agent 开始", {"path": str(target)})
        mining = self.vulnerability_mining_agent.run(target, profile, semantic_index)
        events.extend(mining.events)
        self._emit(
            "VulnerabilityMiningAgent",
            "stage_done",
            "漏洞挖掘 Agent 完成",
            {
                "tools": len(mining.tool_results),
                "dangerous_functions": len(mining.dangerous_functions),
                "program_slices": len(mining.program_slices),
                "candidates": len(mining.candidates),
                "findings": len(mining.findings),
            },
        )

        self._emit("VerificationAgent", "stage_start", "漏洞验证和 PoC 生成开始", {"findings": len(mining.findings)})
        verification_event = AgentEvent(
            agent="VerificationAgent",
            action="verify_and_generate_poc",
            status="running",
        )
        verification = self.verification_agent.verify(target, mining.findings, output_dir, profile, runtime_url)
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
            tool_results=mining.tool_results,
            dangerous_functions=mining.dangerous_functions,
            program_slices=mining.program_slices,
            candidates=mining.candidates,
            findings=mining.findings,
            verification_results=verification,
            agent_events=events,
            llm_enabled=self.llm_client.enabled,
            llm_required=True,
            llm_provider=self.settings.llm_provider,
            llm_model=self.settings.llm_model,
        )

    def _emit(self, agent: str, event_type: str, message: str, metadata: dict[str, Any]) -> None:
        if self.event_sink:
            self.event_sink(agent, event_type, message, metadata)
