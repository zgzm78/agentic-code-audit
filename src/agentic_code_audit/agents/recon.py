from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from ..config import Settings
from ..models import AgentEvent, ProjectProfile, ToolResult, utc_now
from ..tools.runner import ToolPlanner, ToolRunner
from .profiler import ProjectProfiler


class ReconInterpreter:
    """Interpret structured profile facts and recon tool summaries without inventing runtime details."""

    def interpret(self, profile: ProjectProfile, recon_tool_results: list[ToolResult]) -> dict[str, Any]:
        summaries = self._dependency_findings_summary(recon_tool_results)
        attack_priorities = self._attack_priorities(profile, summaries)
        verification_hints = self._verification_hints(profile, summaries)
        return {
            "narrative": self._narrative(profile, summaries, attack_priorities),
            "attack_priorities": attack_priorities,
            "verification_hints": verification_hints,
            "dependency_findings_summary": summaries,
        }

    def _dependency_findings_summary(self, tool_results: list[ToolResult]) -> list[dict[str, Any]]:
        summaries: list[dict[str, Any]] = []
        for result in tool_results:
            if result.tool not in {"osv-scanner", "pip-audit", "npm-audit", "cargo-audit", "gosec"}:
                continue
            findings = result.findings or []
            top_ids: list[str] = []
            packages: list[str] = []
            for item in findings[:5]:
                vuln_id = str(
                    item.get("id")
                    or item.get("vulnerability_id")
                    or item.get("rule_id")
                    or item.get("advisory", {}).get("id")
                    or ""
                )
                package = item.get("package") or item.get("name") or item.get("module_name") or ""
                if vuln_id:
                    top_ids.append(vuln_id)
                if package:
                    packages.append(str(package))
            summaries.append(
                {
                    "tool": result.tool,
                    "status": result.status,
                    "count": len(findings),
                    "packages": sorted(set(packages))[:5],
                    "top_ids": top_ids[:5],
                    "summary": result.summary,
                    "tool_run_ref": result.run_id,
                    "artifact_refs": [
                        item
                        for item in [result.stdout_artifact_id, result.stderr_artifact_id, result.parsed_artifact_id]
                        if item
                    ],
                }
            )
        return summaries

    def _attack_priorities(self, profile: ProjectProfile, summaries: list[dict[str, Any]]) -> list[str]:
        priorities: list[str] = []
        if profile.service_entries or any("http" in item for item in profile.attack_surfaces):
            priorities.append("Trace externally reachable handlers before internal helper functions.")
        if any(item.get("count", 0) > 0 for item in summaries):
            priorities.append("Triage reachable dependency findings before speculative source-only issues.")
        if any(language in profile.languages for language in ("C", "C++")):
            priorities.append("Prioritize memory-unsafe parsing, file handling, and argument processing paths.")
        if "Python" in profile.languages:
            priorities.append("Prioritize command execution, deserialization, and file path handling flows.")
        if "JavaScript" in profile.languages or "TypeScript" in profile.languages:
            priorities.append("Prioritize request-to-sink flows across routes, child_process, and filesystem APIs.")
        if not priorities:
            priorities.append("Start from entry points and follow user-controlled data into high-risk sinks.")
        return priorities[:5]

    def _verification_hints(self, profile: ProjectProfile, summaries: list[dict[str, Any]]) -> list[str]:
        hints = list(profile.weak_verification_strategies)
        if profile.non_runnable_reasons:
            hints.extend(f"Constraint: {reason}" for reason in profile.non_runnable_reasons[:3])
        if any(item.get("count", 0) > 0 for item in summaries):
            hints.append("Dependency findings default to evidence confirmation rather than dynamic exploitation.")
        if profile.verification_entries:
            hints.extend(f"Entry: {item.get('kind')}" for item in profile.verification_entries[:3])
        if not hints:
            hints.append("No runnable entry point was confirmed; verification may require a harness.")
        return hints[:6]

    def _narrative(
        self,
        profile: ProjectProfile,
        summaries: list[dict[str, Any]],
        attack_priorities: list[str],
    ) -> str:
        dependency_count = sum(int(item.get("count", 0)) for item in summaries)
        languages = ", ".join(profile.languages.keys()) or "unknown"
        frameworks = ", ".join(profile.frameworks) or "unknown"
        first_priority = attack_priorities[0] if attack_priorities else "Start from entry points."
        return (
            f"Project type: {profile.project_type}; languages: {languages}; frameworks: {frameworks}. "
            f"Dependency/security recon findings: {dependency_count}. {first_priority}"
        )


class ReconAgent:
    def __init__(
        self,
        settings: Settings,
        tool_runner: ToolRunner | None = None,
        tool_planner: ToolPlanner | None = None,
    ):
        self.settings = settings
        self.profiler = ProjectProfiler(settings)
        self.tool_runner = tool_runner or ToolRunner(settings)
        self.tool_planner = tool_planner or ToolPlanner(self.tool_runner.registry, self.tool_runner.env)
        self.interpreter = ReconInterpreter()

    def run(self, target: Path) -> tuple[ProjectProfile, AgentEvent]:
        event = AgentEvent(agent="ReconAgent", action="profile_project", status="running", phase="profile_project")
        profile = self.profiler.profile(target)
        availability = self.tool_planner.list_available_tools(profile)
        profile.tool_availability = [asdict(item) for item in availability]
        recommendations = self.tool_planner.recommend_tools("ReconAgent", "profile_project", profile, target)
        recon_tool_results = self._run_recon_tools(target, recommendations)
        interpreted = self.interpreter.interpret(profile, recon_tool_results)

        profile.attack_surfaces = self._attack_surfaces(profile)
        profile.recommended_tools = [item.name for item in recommendations]
        profile.recommended_tool_details = [self._recommendation_detail(item) for item in recommendations]
        profile.dependency_findings_summary = interpreted["dependency_findings_summary"]
        profile.attack_priorities = interpreted["attack_priorities"]
        profile.verification_hints = interpreted["verification_hints"]
        profile.recon_evidence_refs = self._recon_evidence_refs(recon_tool_results)
        profile.profile_summary = self._profile_summary(profile, interpreted["narrative"])

        event.status = "completed"
        event.detail = (
            f"languages={profile.languages}; project_type={profile.project_type}; "
            f"build_entries={len(profile.build_entries)}; runtime_entries={len(profile.runtime_entries)}; "
            f"verification_entries={len(profile.verification_entries)}; recon_tools={len(recon_tool_results)}"
        )
        event.phase = "profile_project"
        event.finished_at = utc_now()
        return profile, event

    def _run_recon_tools(self, target: Path, recommendations: list[Any]) -> list[ToolResult]:
        results: list[ToolResult] = []
        runnable = {"osv-scanner", "pip-audit", "npm-audit", "cargo-audit", "gosec"}
        invocations = self.tool_planner.build_invocations(
            [item for item in recommendations if item.name in runnable],
            target,
        )
        for invocation in invocations:
            results.append(self.tool_runner.run(invocation))
        return results

    def _recommendation_detail(self, item: Any) -> dict[str, Any]:
        return {
            "name": item.name,
            "available": item.available,
            "required": item.required,
            "reason": item.reason,
            "intended_phase": item.intended_phase,
        }

    def _recon_evidence_refs(self, results: list[ToolResult]) -> list[str]:
        refs: list[str] = []
        for result in results:
            refs.append(result.run_id)
            refs.extend(item for item in [result.stdout_artifact_id, result.stderr_artifact_id, result.parsed_artifact_id] if item)
        return [item for item in refs if item]

    def _attack_surfaces(self, profile: ProjectProfile) -> list[str]:
        surfaces: list[str] = []
        if profile.entry_points:
            surfaces.append("web_or_cli_entry_points")
        if any("upload" in path.lower() or "file" in path.lower() for path in profile.high_risk_files):
            surfaces.append("file_upload_or_file_access")
        if any("auth" in path.lower() or "login" in path.lower() for path in profile.high_risk_files):
            surfaces.append("authentication")
        if any("api" in path.lower() or "route" in path.lower() for path in profile.high_risk_files):
            surfaces.append("http_api")
        if profile.package_files:
            surfaces.append("dependency_supply_chain")
        if profile.container_files:
            surfaces.append("container_or_deployment")
        if profile.service_entries:
            surfaces.append("http_service")
        if profile.runtime_entries:
            surfaces.append("cli_or_runtime_entry")
        if profile.library_entries:
            surfaces.append("library_api")
        return sorted(set(surfaces))

    def _profile_summary(self, profile: ProjectProfile, narrative: str) -> dict[str, Any]:
        available_tools = [item["name"] for item in profile.tool_availability if item.get("available")]
        missing_required = [
            item["name"]
            for item in profile.tool_availability
            if item.get("required") and not item.get("available")
        ]
        return {
            "project_type": profile.project_type,
            "languages": profile.languages,
            "frameworks": profile.frameworks,
            "build_entries": len(profile.build_entries),
            "runtime_entries": len(profile.runtime_entries),
            "test_entries": len(profile.test_entries),
            "verification_entries": len(profile.verification_entries),
            "non_runnable_reasons": profile.non_runnable_reasons,
            "weak_verification_strategies": profile.weak_verification_strategies,
            "available_tools": available_tools,
            "missing_required_tools": missing_required,
            "narrative": narrative,
        }
