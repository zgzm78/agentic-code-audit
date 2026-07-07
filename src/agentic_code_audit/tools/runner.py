from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from ..config import Settings
from ..models import ToolResult, utc_now


class CommandRunner:
    def __init__(self, settings: Settings):
        self.settings = settings

    def run_json_tool(self, tool: str, command: list[str], cwd: Path) -> ToolResult:
        if not shutil.which(command[0]):
            return ToolResult(
                tool=tool,
                status="skipped",
                command=command,
                summary=f"{command[0]} is not installed or not in PATH.",
                finished_at=utc_now(),
            )

        try:
            proc = subprocess.run(
                command,
                cwd=str(cwd),
                text=True,
                capture_output=True,
                timeout=self.settings.tool_timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool=tool,
                status="timeout",
                command=command,
                summary=f"{tool} timed out after {self.settings.tool_timeout}s.",
                finished_at=utc_now(),
            )

        raw_text = proc.stdout.strip() or proc.stderr.strip()
        parsed = self._parse_json(raw_text)
        status = "ok" if proc.returncode in (0, 1) else "error"
        return ToolResult(
            tool=tool,
            status=status,
            command=command,
            summary=f"exit_code={proc.returncode}",
            raw=parsed if parsed is not None else raw_text[:8000],
            finished_at=utc_now(),
        )

    def _parse_json(self, text: str):
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None


class SecurityToolRunner:
    def __init__(self, settings: Settings):
        self.command_runner = CommandRunner(settings)

    def run_all(self, target: Path) -> list[ToolResult]:
        target = target.resolve()
        results = [
            self.run_semgrep(target),
            self.run_gitleaks(target),
            self.run_osv_scanner(target),
        ]
        if self._has_python_project(target):
            results.append(self.run_bandit(target))
        if (target / "package.json").exists():
            results.append(self.run_npm_audit(target))
        return results

    def run_semgrep(self, target: Path) -> ToolResult:
        return self.command_runner.run_json_tool(
            "semgrep",
            ["semgrep", "scan", "--json", "--config", "auto", str(target)],
            target,
        )

    def run_gitleaks(self, target: Path) -> ToolResult:
        return self.command_runner.run_json_tool(
            "gitleaks",
            ["gitleaks", "detect", "--source", str(target), "--report-format", "json", "--no-git"],
            target,
        )

    def run_osv_scanner(self, target: Path) -> ToolResult:
        return self.command_runner.run_json_tool(
            "osv-scanner",
            ["osv-scanner", "--format", "json", "--recursive", str(target)],
            target,
        )

    def run_bandit(self, target: Path) -> ToolResult:
        return self.command_runner.run_json_tool(
            "bandit",
            ["bandit", "-r", str(target), "-f", "json"],
            target,
        )

    def run_npm_audit(self, target: Path) -> ToolResult:
        return self.command_runner.run_json_tool("npm-audit", ["npm", "audit", "--json"], target)

    def _has_python_project(self, target: Path) -> bool:
        return any((target / name).exists() for name in ("requirements.txt", "pyproject.toml", "Pipfile"))
