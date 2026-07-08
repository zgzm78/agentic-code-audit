from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Callable

from ..config import Settings
from ..models import ToolResult, utc_now


class CommandRunner:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.env = self._build_env()

    def run_json_tool(self, tool: str, command: list[str], cwd: Path) -> ToolResult:
        executable = shutil.which(command[0], path=self.env.get("PATH"))
        if not executable:
            return ToolResult(
                tool=tool,
                status="skipped",
                command=command,
                summary=f"{command[0]} is not installed or not in PATH.",
                finished_at=utc_now(),
            )

        try:
            resolved_command = [executable, *command[1:]]
            proc = subprocess.run(
                resolved_command,
                cwd=str(cwd),
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=self.settings.tool_timeout,
                check=False,
                env=self.env,
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

    def _build_env(self) -> dict[str, str]:
        env = os.environ.copy()
        app_root = Path.cwd()
        local_paths = [
            app_root / ".tools" / "bin",
            app_root / ".tools" / "semgrep-venv" / "Scripts",
        ]
        existing = env.get("PATH", "")
        env["PATH"] = os.pathsep.join([str(path) for path in local_paths if path.exists()] + [existing])
        for key, env_names in {
            "http.proxy": ("HTTP_PROXY", "http_proxy"),
            "https.proxy": ("HTTPS_PROXY", "https_proxy"),
        }.items():
            proxy = self._read_git_config(key)
            if proxy:
                for env_name in env_names:
                    env.setdefault(env_name, proxy)
        return env

    def _read_git_config(self, key: str) -> str:
        try:
            proc = subprocess.run(
                ["git", "config", "--get", key],
                cwd=str(Path.cwd()),
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return ""
        return proc.stdout.strip() if proc.returncode == 0 else ""


class SecurityToolRunner:
    def __init__(
        self,
        settings: Settings,
        event_sink: Callable[[str, str, str, dict[str, Any]], None] | None = None,
    ):
        self.command_runner = CommandRunner(settings)
        self.event_sink = event_sink

    def run_all(self, target: Path) -> list[ToolResult]:
        target = target.resolve()
        results = [
            self._run_tool("semgrep", "Semgrep 静态规则扫描开始", lambda: self.run_semgrep(target)),
            self._run_tool("gitleaks", "Gitleaks 凭据泄露扫描开始", lambda: self.run_gitleaks(target)),
            self._run_tool("osv-scanner", "OSV 依赖漏洞扫描开始", lambda: self.run_osv_scanner(target)),
        ]
        if self._has_python_project(target):
            results.append(self._run_tool("bandit", "Bandit Python 安全扫描开始", lambda: self.run_bandit(target)))
        if (target / "package.json").exists():
            results.append(self._run_tool("npm-audit", "npm audit 依赖扫描开始", lambda: self.run_npm_audit(target)))
        return results

    def _run_tool(self, tool: str, start_message: str, fn) -> ToolResult:
        self._emit("ToolAgent", "tool_start", start_message, {"tool": tool})
        result = fn()
        self._emit(
            "ToolAgent",
            "tool_end",
            f"{tool} 完成: {result.status}; {result.summary}",
            {"tool": tool, "status": result.status, "summary": result.summary, "command": result.command},
        )
        return result

    def _emit(self, agent: str, event_type: str, message: str, metadata: dict[str, Any]) -> None:
        if self.event_sink:
            self.event_sink(agent, event_type, message, metadata)

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
            [
                "osv-scanner",
                "scan",
                "source",
                "--format",
                "json",
                "--recursive",
                "--allow-no-lockfiles",
                str(target),
            ],
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
