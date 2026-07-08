from __future__ import annotations

from pathlib import Path

from ..config import Settings
from ..models import AgentEvent, ProjectProfile, utc_now
from .profiler import ProjectProfiler


class ReconAgent:
    def __init__(self, settings: Settings):
        self.profiler = ProjectProfiler(settings)

    def run(self, target: Path) -> tuple[ProjectProfile, AgentEvent]:
        event = AgentEvent(agent="ReconAgent", action="profile_project", status="running")
        profile = self.profiler.profile(target)
        profile.attack_surfaces = self._attack_surfaces(profile)
        profile.recommended_tools = self._recommended_tools(profile)
        event.status = "completed"
        event.detail = (
            f"languages={profile.languages}; frameworks={profile.frameworks}; "
            f"attack_surfaces={profile.attack_surfaces}"
        )
        event.finished_at = utc_now()
        return profile, event

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
        return sorted(set(surfaces))

    def _recommended_tools(self, profile: ProjectProfile) -> list[str]:
        tools = ["builtin-patterns", "semgrep", "gitleaks", "osv-scanner"]
        if "Python" in profile.languages:
            tools.extend(["bandit", "pip-audit", "safety"])
        if "JavaScript" in profile.languages or "TypeScript" in profile.languages:
            tools.extend(["npm audit"])
        return sorted(set(tools))
