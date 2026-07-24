from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import Settings
from .models import ProjectProfile, ToolResult, normalize_path


LANGUAGE_TO_CODEQL = {
    "C": ("cpp", "codeql/cpp-queries"),
    "C++": ("cpp", "codeql/cpp-queries"),
    "C/C++": ("cpp", "codeql/cpp-queries"),
    "Python": ("python", "codeql/python-queries"),
    "JavaScript": ("javascript-typescript", "codeql/javascript-queries"),
    "TypeScript": ("javascript-typescript", "codeql/javascript-queries"),
    "Java": ("java-kotlin", "codeql/java-queries"),
    "Kotlin": ("java-kotlin", "codeql/java-queries"),
    "Go": ("go", "codeql/go-queries"),
}


@dataclass
class CodeQLPathEvidence:
    rule_id: str
    message: str
    file_path: str
    line_start: int
    severity: str = ""
    sink: str = ""
    source: str = ""
    path: list[dict[str, Any]] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_finding(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "message": self.message,
            "file": self.file_path,
            "path": self.file_path,
            "line": self.line_start,
            "severity": self.severity,
            "sink": self.sink or self.rule_id,
            "source": self.source,
            "code_flow": [dict(item) for item in self.path],
            "raw": self.raw,
        }


class CodeQLAnalyzer:
    """Run CodeQL CLI and normalize SARIF path evidence."""

    def __init__(self, settings: Settings | None = None, work_dir: Path | None = None) -> None:
        self.settings = settings or Settings.load()
        self.work_dir = work_dir
        self._prepared_packs: set[str] = set()

    def available(self) -> bool:
        return self._executable() is not None

    def run(self, target: Path, profile: ProjectProfile) -> tuple[ToolResult, list[CodeQLPathEvidence]]:
        started = time.monotonic()
        executable = self._executable()
        run_id = f"codeql-{int(time.time() * 1000)}"
        if not getattr(self.settings, "enable_codeql", True):
            return (
                ToolResult(
                    tool="codeql",
                    status="skipped",
                    run_id=run_id,
                    summary="CodeQL disabled by AUDIT_ENABLE_CODEQL",
                    duration_ms=self._duration(started),
                ),
                [],
            )
        if not executable:
            return (
                ToolResult(
                    tool="codeql",
                    status="skipped",
                    run_id=run_id,
                    summary="codeql executable not installed",
                    duration_ms=self._duration(started),
                ),
                [],
            )

        languages = self._languages(profile, target)
        if not languages:
            return (
                ToolResult(
                    tool="codeql",
                    status="skipped",
                    run_id=run_id,
                    summary="no CodeQL-supported language detected",
                    duration_ms=self._duration(started),
                ),
                [],
            )

        root = Path(self.work_dir or tempfile.mkdtemp(prefix="agentic-codeql-"))
        root.mkdir(parents=True, exist_ok=True)
        all_evidence: list[CodeQLPathEvidence] = []
        raw_runs: list[dict[str, Any]] = []
        commands: list[list[str]] = []
        worst_exit = 0
        status = "ok"
        for codeql_language, query_pack in languages:
            db_dir = root / f"db-{codeql_language}"
            sarif_path = root / f"{codeql_language}.sarif"
            create_command = [
                executable,
                "database",
                "create",
                str(db_dir),
                "--overwrite",
                "--source-root",
                str(target),
                "--language",
                codeql_language,
            ]
            if codeql_language == "cpp":
                create_command.append("--build-mode=none")
            create_proc = self._run_command(create_command)
            commands.append(create_command)
            raw_entry = {
                "language": codeql_language,
                "query_pack": query_pack,
                "database": str(db_dir),
                "sarif": str(sarif_path),
                "create": self._proc_record(create_proc),
            }
            worst_exit = max(worst_exit, int(create_proc.returncode or 0))
            if create_proc.returncode != 0 and codeql_language == "cpp" and "--build-mode=none" in create_command:
                fallback_command = [item for item in create_command if item != "--build-mode=none"]
                create_proc = self._run_command(fallback_command)
                commands.append(fallback_command)
                raw_entry["create_fallback"] = self._proc_record(create_proc)
                worst_exit = max(worst_exit, int(create_proc.returncode or 0))
            if create_proc.returncode != 0:
                status = "failed"
                raw_runs.append(raw_entry)
                continue

            pack_proc = self._prepare_query_pack(executable, query_pack)
            if pack_proc is not None:
                commands.append(list(pack_proc.args) if isinstance(pack_proc.args, list) else [str(pack_proc.args)])
                raw_entry["query_pack_prepare"] = self._proc_record(pack_proc)

            analyze_command = [
                executable,
                "database",
                "analyze",
                str(db_dir),
                query_pack,
                "--format=sarif-latest",
                f"--output={sarif_path}",
            ]
            analyze_proc = self._run_command(analyze_command)
            commands.append(analyze_command)
            raw_entry["analyze"] = self._proc_record(analyze_proc)
            worst_exit = max(worst_exit, int(analyze_proc.returncode or 0))
            if analyze_proc.returncode != 0:
                status = "failed"
                raw_runs.append(raw_entry)
                continue
            parsed = self.parse_sarif(sarif_path, target)
            raw_entry["findings"] = [item.to_finding() for item in parsed]
            all_evidence.extend(parsed)
            raw_runs.append(raw_entry)

        summary = f"CodeQL languages={','.join(lang for lang, _pack in languages)} findings={len(all_evidence)}"
        result = ToolResult(
            tool="codeql",
            status=status,
            run_id=run_id,
            command=commands[-1] if commands else [],
            summary=summary,
            raw={"runs": raw_runs, "work_dir": str(root), "commands": commands},
            findings=[item.to_finding() for item in all_evidence],
            exit_code=worst_exit,
            duration_ms=self._duration(started),
            parsed_artifact_id=str(root),
        )
        return result, all_evidence

    def _executable(self) -> str | None:
        executable = shutil.which("codeql")
        if executable:
            return executable
        candidates = [
            Path.cwd() / ".tools" / "codeql" / "codeql",
            Path("/app/.tools/codeql/codeql"),
        ]
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)
        return None

    def _prepare_query_pack(self, executable: str, query_pack: str) -> subprocess.CompletedProcess[str] | None:
        if query_pack in self._prepared_packs:
            return None
        self._prepared_packs.add(query_pack)
        if not getattr(self.settings, "codeql_pack_download", True):
            return None
        return self._run_command([executable, "pack", "download", query_pack])

    def parse_sarif(self, sarif_path: Path, target: Path | None = None) -> list[CodeQLPathEvidence]:
        try:
            payload = json.loads(sarif_path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            return []
        rules = self._rules_by_id(payload)
        output: list[CodeQLPathEvidence] = []
        for run in payload.get("runs", []) or []:
            if not isinstance(run, dict):
                continue
            for result in run.get("results", []) or []:
                if not isinstance(result, dict):
                    continue
                rule_id = str(result.get("ruleId") or result.get("rule", {}).get("id") or "codeql")
                message = self._message(result.get("message"))
                location = self._primary_location(result)
                file_path = self._normalize_location_path(location.get("uri", ""), target)
                line = self._int(location.get("line"), 1)
                code_flow = self._code_flow(result, target)
                source = code_flow[0].get("message", "") if code_flow else ""
                sink = code_flow[-1].get("message", "") if code_flow else rule_id
                severity = str(rules.get(rule_id, {}).get("defaultConfiguration", {}).get("level") or result.get("level") or "")
                output.append(
                    CodeQLPathEvidence(
                        rule_id=rule_id,
                        message=message,
                        file_path=file_path,
                        line_start=line,
                        severity=severity,
                        sink=sink,
                        source=source,
                        path=code_flow,
                        raw=result,
                    )
                )
        return output

    def _languages(self, profile: ProjectProfile, target: Path) -> list[tuple[str, str]]:
        names = list((profile.languages or {}).keys())
        if not names:
            names = self._languages_from_files(target)
        pairs: list[tuple[str, str]] = []
        seen: set[str] = set()
        for name in names:
            pair = LANGUAGE_TO_CODEQL.get(str(name))
            if not pair or pair[0] in seen:
                continue
            seen.add(pair[0])
            pairs.append(pair)
        return pairs

    def _languages_from_files(self, target: Path) -> list[str]:
        suffix_map = {
            ".c": "C",
            ".cc": "C++",
            ".cpp": "C++",
            ".cxx": "C++",
            ".h": "C/C++",
            ".hpp": "C++",
            ".py": "Python",
            ".js": "JavaScript",
            ".jsx": "JavaScript",
            ".ts": "TypeScript",
            ".tsx": "TypeScript",
            ".java": "Java",
            ".kt": "Kotlin",
            ".go": "Go",
        }
        values: list[str] = []
        for path in target.rglob("*"):
            if not path.is_file() or ".git" in path.parts:
                continue
            language = suffix_map.get(path.suffix.lower())
            if language:
                values.append(language)
        return list(dict.fromkeys(values))

    def _run_command(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                command,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=getattr(self.settings, "codeql_timeout", 600),
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return subprocess.CompletedProcess(
                command,
                returncode=124,
                stdout=exc.stdout or "",
                stderr=exc.stderr or "CodeQL command timed out",
            )
        except OSError as exc:
            return subprocess.CompletedProcess(command, returncode=127, stdout="", stderr=str(exc))

    def _proc_record(self, proc: subprocess.CompletedProcess[str]) -> dict[str, Any]:
        return {
            "command": list(proc.args) if isinstance(proc.args, list) else [str(proc.args)],
            "exit_code": proc.returncode,
            "stdout": (proc.stdout or "")[-8000:],
            "stderr": (proc.stderr or "")[-8000:],
        }

    def _rules_by_id(self, payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
        rules: dict[str, dict[str, Any]] = {}
        for run in payload.get("runs", []) or []:
            tool = run.get("tool", {}) if isinstance(run, dict) else {}
            driver = tool.get("driver", {}) if isinstance(tool, dict) else {}
            for rule in driver.get("rules", []) or []:
                if isinstance(rule, dict) and rule.get("id"):
                    rules[str(rule["id"])] = rule
        return rules

    def _primary_location(self, result: dict[str, Any]) -> dict[str, Any]:
        locations = result.get("locations", []) or []
        if not locations:
            return {}
        physical = (locations[0] or {}).get("physicalLocation", {}) or {}
        artifact = physical.get("artifactLocation", {}) or {}
        region = physical.get("region", {}) or {}
        return {"uri": artifact.get("uri", ""), "line": region.get("startLine")}

    def _code_flow(self, result: dict[str, Any], target: Path | None) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        for code_flow in result.get("codeFlows", []) or []:
            for thread_flow in code_flow.get("threadFlows", []) or []:
                for location in thread_flow.get("locations", []) or []:
                    if not isinstance(location, dict):
                        continue
                    loc = location.get("location", {}) or {}
                    physical = loc.get("physicalLocation", {}) or {}
                    artifact = physical.get("artifactLocation", {}) or {}
                    region = physical.get("region", {}) or {}
                    output.append(
                        {
                            "file_path": self._normalize_location_path(str(artifact.get("uri") or ""), target),
                            "line": self._int(region.get("startLine"), 1),
                            "message": self._message(loc.get("message") or location.get("message")),
                        }
                    )
        return output[:80]

    def _normalize_location_path(self, value: str, target: Path | None) -> str:
        if not value:
            return ""
        path = Path(value)
        if target and path.is_absolute():
            return normalize_path(path, target)
        return value.replace("\\", "/")

    def _message(self, value: Any) -> str:
        if isinstance(value, dict):
            return str(value.get("text") or value.get("markdown") or "")
        return str(value or "")

    def _duration(self, started: float) -> int:
        return int((time.monotonic() - started) * 1000)

    def _int(self, value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default
