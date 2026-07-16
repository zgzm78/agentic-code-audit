from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..config import Settings
from ..models import ArtifactRecord, ProjectProfile, ToolResult, utc_now

# ---------------------------------------------------------------------------
# Tools that must execute inside the sandbox container (docker exec)
# Everything else runs locally in the backend process.
# ---------------------------------------------------------------------------
SANDBOX_TOOLS: set[str] = {
    # C/C++ static analysis
    "cppcheck",
    "clang-tidy",
    # C/C++ build chain
    "cmake",
    "make",
    "ninja",
    "gcc",
    "g++",
    "clang",
    "clang++",
    "pkg-config",
    # C/C++ debugging / verification
    "valgrind",
    "gdb",
    "lldb",
    # Code navigation
    "ctags",
    # Multi-language runtimes (not installed in backend)
    "go",
    "gosec",
    "cargo",
    "cargo-audit",
    "java",
    "mvn",
    "gradle",
    "php",
    "composer",
}

# Path translation: backend container → sandbox container (Docker volumes)
SANDBOX_PATH_MAP: list[tuple[str, str]] = [
    ("/app/runs", "/workspace/runs"),
    ("/app/reports", "/workspace/reports"),
]


def _translate_path_for_sandbox(host_path: str) -> str:
    """Map a backend-container path into the corresponding sandbox-container path."""
    for backend_prefix, sandbox_prefix in SANDBOX_PATH_MAP:
        if host_path.startswith(backend_prefix):
            return sandbox_prefix + host_path[len(backend_prefix):]
    return host_path


def _translate_command_for_sandbox(command: list[str]) -> list[str]:
    """Translate all path-like arguments in a command for sandbox execution."""
    translated: list[str] = []
    for arg in command:
        translated.append(_translate_path_for_sandbox(arg))
    return translated


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    executable: str
    capability: str
    required: bool = False
    languages: tuple[str, ...] = ()
    default_timeout: int | None = None
    version_args: tuple[str, ...] = ("--version",)
    parser: str = "generic"
    cacheable: bool = True


@dataclass
class ToolAvailability:
    name: str
    executable: str
    available: bool
    required: bool
    capability: str
    version: str = ""
    path: str = ""
    reason: str = ""
    execution_location: str = "backend"
    container: str = ""
    network_policy: str = "default"


@dataclass
class ToolInvocation:
    tool: str
    command: list[str]
    cwd: Path
    parser: str = "generic"
    timeout: int | None = None
    cacheable: bool = True
    env: dict[str, str] = field(default_factory=dict)


@dataclass
class ToolRecommendation:
    name: str
    available: bool
    required: bool
    reason: str
    intended_phase: str
    capability: str
    languages: tuple[str, ...] = ()
    default_timeout: int | None = None
    parser: str = "generic"


class ToolRegistry:
    """Registry of tools that agents can request by capability."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolDefinition] = {}
        self._register_defaults()

    def register(self, definition: ToolDefinition) -> None:
        self._tools[definition.name] = definition

    def get(self, name: str) -> ToolDefinition:
        return self._tools[name]

    def all(self) -> list[ToolDefinition]:
        return list(self._tools.values())

    def recommend_for_project(self, target: Path) -> list[ToolDefinition]:
        return [self._tools[name] for name in self._project_tool_names(target) if name in self._tools]

    def availability(self, env: dict[str, str]) -> list[ToolAvailability]:
        return [self.check_tool(tool.name, env) for tool in self.all()]

    def check_tool(self, name: str, env: dict[str, str]) -> ToolAvailability:
        definition = self.get(name)
        executable = shutil.which(definition.executable, path=env.get("PATH"))
        if not executable:
            return ToolAvailability(
                name=definition.name,
                executable=definition.executable,
                available=False,
                required=definition.required,
                capability=definition.capability,
                reason=f"{definition.executable} is not installed or not in PATH.",
            )
        version = self._read_version([executable, *definition.version_args], env)
        return ToolAvailability(
            name=definition.name,
            executable=definition.executable,
            available=True,
            required=definition.required,
            capability=definition.capability,
            version=version,
            path=executable,
        )

    def build_invocation(self, name: str, target: Path) -> ToolInvocation:
        definition = self.get(name)
        target = target.resolve()
        commands = {
            "rg": ["rg", "-n", "--hidden", "--glob", "!.git", "--glob", "!node_modules", "TODO|FIXME", str(target)],
            "semgrep": ["semgrep", "scan", "--json", "--config", "auto", str(target)],
            "gitleaks": ["gitleaks", "detect", "--source", str(target), "--report-format", "json", "--no-git"],
            "osv-scanner": [
                "osv-scanner",
                "scan",
                "source",
                "--format",
                "json",
                "--recursive",
                "--allow-no-lockfiles",
                str(target),
            ],
            "trivy": ["trivy", "fs", "--format", "json", "--quiet", "--scanners", "vuln", str(target)],
            "bandit": ["bandit", "-r", str(target), "-f", "json"],
            "npm-audit": ["npm", "audit", "--json"],
            "cppcheck": [
                "cppcheck",
                "--enable=all",
                "--xml",
                "--xml-version=2",
                "--inline-suppr",
                str(target),
            ],
            "clang-tidy": ["clang-tidy", "-p", str(target), str(target)],
            "pip-audit": self._pip_audit_command(target),
            "gosec": ["gosec", "-fmt=json", "./..."],
            "cargo-audit": ["cargo", "audit", "--json"],
            "docker": ["docker", "--version"],
            "cmake": ["cmake", "--version"],
            "ninja": ["ninja", "--version"],
            "make": ["make", "--version"],
            "gcc": ["gcc", "--version"],
            "g++": ["g++", "--version"],
            "clang": ["clang", "--version"],
            "clang++": ["clang++", "--version"],
            "ctags": ["ctags", "--version"],
            "valgrind": ["valgrind", "--version"],
            "gdb": ["gdb", "--version"],
            "lldb": ["lldb", "--version"],
            "pytest": ["pytest", "--version"],
            "node": ["node", "--version"],
            "npm": ["npm", "--version"],
            "curl": ["curl", "--version"],
            "sqlite3": ["sqlite3", "--version"],
            "go": ["go", "version"],
            "cargo": ["cargo", "--version"],
            "java": ["java", "-version"],
            "mvn": ["mvn", "--version"],
            "gradle": ["gradle", "--version"],
            "php": ["php", "--version"],
            "composer": ["composer", "--version"],
        }
        command = commands.get(name, [definition.executable, *definition.version_args])
        return ToolInvocation(
            tool=definition.name,
            command=command,
            cwd=target,
            parser=definition.parser,
            timeout=definition.default_timeout,
            cacheable=definition.cacheable,
        )

    def _register_defaults(self) -> None:
        self.register(
            ToolDefinition(
                name="rg",
                executable="rg",
                capability="fast-code-search",
                required=True,
                parser="text",
                cacheable=False,
            )
        )
        self.register(
            ToolDefinition(
                name="semgrep",
                executable="semgrep",
                capability="static-analysis",
                required=True,
                parser="semgrep",
            )
        )
        self.register(
            ToolDefinition(
                name="gitleaks",
                executable="gitleaks",
                capability="secret-scan",
                required=True,
                parser="gitleaks",
                version_args=("version",),
            )
        )
        self.register(
            ToolDefinition(
                name="osv-scanner",
                executable="osv-scanner",
                capability="dependency-vulnerability",
                required=True,
                parser="osv-scanner",
            )
        )
        self.register(
            ToolDefinition(
                name="bandit",
                executable="bandit",
                capability="python-static-analysis",
                languages=("Python",),
                parser="bandit",
            )
        )
        self.register(
            ToolDefinition(
                name="npm-audit",
                executable="npm",
                capability="node-dependency-vulnerability",
                languages=("JavaScript", "TypeScript"),
                parser="npm-audit",
                version_args=("--version",),
            )
        )
        for name, executable, capability in [
            ("cppcheck", "cppcheck", "cpp-static-analysis"),
            ("clang-tidy", "clang-tidy", "cpp-static-analysis"),
            ("codeql", "codeql", "semantic-code-analysis"),
            ("joern", "joern", "cpg-analysis"),
            ("trivy", "trivy", "filesystem-vulnerability"),
            ("syft", "syft", "sbom"),
            ("pip-audit", "pip-audit", "python-dependency-vulnerability"),
            ("gosec", "gosec", "go-static-analysis"),
            ("cargo-audit", "cargo", "rust-dependency-vulnerability"),
        ]:
            parser = "clang-tidy" if name == "clang-tidy" else ("text" if name == "codeql" else name)
            self.register(ToolDefinition(name=name, executable=executable, capability=capability, parser=parser))
        for name, executable, capability, languages in [
            ("docker", "docker", "environment", ()),
            ("cmake", "cmake", "build", ("C", "C++")),
            ("ninja", "ninja", "build", ("C", "C++")),
            ("make", "make", "build", ("C", "C++")),
            ("gcc", "gcc", "build", ("C",)),
            ("g++", "g++", "build", ("C++",)),
            ("clang", "clang", "build", ("C",)),
            ("clang++", "clang++", "build", ("C++",)),
            ("ctags", "ctags", "code-navigation", ("C", "C++")),
            ("valgrind", "valgrind", "verification", ("C", "C++")),
            ("gdb", "gdb", "verification", ("C", "C++")),
            ("lldb", "lldb", "verification", ("C", "C++")),
            ("pytest", "pytest", "verification", ("Python",)),
            ("node", "node", "verification", ("JavaScript", "TypeScript")),
            ("npm", "npm", "verification", ("JavaScript", "TypeScript")),
            ("curl", "curl", "verification", ()),
            ("sqlite3", "sqlite3", "verification", ()),
            ("go", "go", "environment", ("Go",)),
            ("cargo", "cargo", "environment", ("Rust",)),
            ("java", "java", "environment", ("Java",)),
            ("mvn", "mvn", "build", ("Java",)),
            ("gradle", "gradle", "build", ("Java",)),
            ("php", "php", "environment", ("PHP",)),
            ("composer", "composer", "build", ("PHP",)),
        ]:
            self.register(
                ToolDefinition(
                    name=name,
                    executable=executable,
                    capability=capability,
                    languages=languages,
                    default_timeout=30,
                    parser="text",
                    cacheable=False,
                )
            )

    def _project_tool_names(self, target: Path) -> list[str]:
        selected = ["rg", "semgrep", "gitleaks", "osv-scanner", "trivy"]
        if self._has_python_project(target):
            selected.extend(["bandit", "pip-audit"])
        if (target / "package.json").exists():
            selected.append("npm-audit")
        if self._has_cpp_project(target):
            selected.append("cppcheck")
            if (target / "compile_commands.json").exists():
                selected.append("clang-tidy")
        if self._has_any_file(target, ("*.go",)):
            selected.append("gosec")
        if (target / "Cargo.lock").exists() or (target / "Cargo.toml").exists():
            selected.append("cargo-audit")
        return list(dict.fromkeys(selected))

    def _read_version(self, command: list[str], env: dict[str, str]) -> str:
        try:
            proc = subprocess.run(
                command,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=10,
                check=False,
                env=env,
            )
        except (OSError, subprocess.TimeoutExpired):
            return ""
        text = (proc.stdout or proc.stderr).strip().splitlines()
        return text[0][:200] if text else ""

    def _has_python_project(self, target: Path) -> bool:
        return any((target / name).exists() for name in ("requirements.txt", "pyproject.toml", "Pipfile"))

    def _has_cpp_project(self, target: Path) -> bool:
        markers = ("CMakeLists.txt", "Makefile", "configure", "meson.build")
        if any((target / name).exists() for name in markers):
            return True
        return self._has_any_file(target, ("*.c", "*.cc", "*.cpp", "*.cxx", "*.h", "*.hpp"))

    def _has_any_file(self, target: Path, patterns: tuple[str, ...]) -> bool:
        for pattern in patterns:
            if next(target.rglob(pattern), None) is not None:
                return True
        return False

    def _pip_audit_command(self, target: Path) -> list[str]:
        requirements = target / "requirements.txt"
        if requirements.exists():
            return ["pip-audit", "--format", "json", "--progress-spinner", "off", "-r", str(requirements)]
        return ["pip-audit", "--format", "json", "--progress-spinner", "off"]


class ToolPlanner:
    """Plan which tools to run for a given phase while preserving registry semantics."""

    def __init__(
        self,
        registry: ToolRegistry,
        env: dict[str, str],
        availability_provider: Callable[[], list[ToolAvailability]] | None = None,
    ):
        self.registry = registry
        self.env = env
        self.availability_provider = availability_provider

    def list_available_tools(self, profile: ProjectProfile | None = None) -> list[ToolAvailability]:
        if self.availability_provider:
            return self.availability_provider()
        return self.registry.availability(self.env)

    def recommend_tools(
        self,
        agent: str,
        phase: str,
        profile: ProjectProfile | None,
        target: Path,
    ) -> list[ToolRecommendation]:
        target = target.resolve()
        definitions = self._recommend_definitions(agent, phase, profile, target)
        availability = {item.name: item for item in self.list_available_tools(profile)}
        recommendations: list[ToolRecommendation] = []
        for definition in definitions:
            item = availability.get(definition.name) or ToolAvailability(
                name=definition.name,
                executable=definition.executable,
                available=False,
                required=definition.required,
                capability=definition.capability,
            )
            recommendations.append(
                ToolRecommendation(
                    name=definition.name,
                    available=item.available,
                    required=definition.required,
                    reason=self._reason_for(definition, phase, profile, target, item),
                    intended_phase=phase,
                    capability=definition.capability,
                    languages=definition.languages,
                    default_timeout=definition.default_timeout,
                    parser=definition.parser,
                )
            )
        return recommendations

    def build_invocations(self, recommendation_set: list[ToolRecommendation], target: Path) -> list[ToolInvocation]:
        return [self.registry.build_invocation(item.name, target) for item in recommendation_set]

    def _recommend_definitions(
        self,
        agent: str,
        phase: str,
        profile: ProjectProfile | None,
        target: Path,
    ) -> list[ToolDefinition]:
        base = [self.registry.get(name) for name in self.registry._project_tool_names(target) if name in self.registry._tools]
        if phase == "profile_project" or agent == "ReconAgent":
            names = ["gitleaks", "osv-scanner"]
            if self._has_python_manifest(target):
                names.append("pip-audit")
            if (target / "package.json").exists():
                names.append("npm-audit")
            if (target / "Cargo.toml").exists() or (target / "Cargo.lock").exists():
                names.append("cargo-audit")
            if self.registry._has_any_file(target, ("*.go",)):
                names.append("gosec")
            return [self.registry.get(name) for name in dict.fromkeys(names) if name in self.registry._tools]
        if phase == "mine_vulnerabilities" or agent == "VulnerabilityMiningAgent":
            names = ["rg", "semgrep", "gitleaks"]
            for item in base:
                if item.name not in names:
                    names.append(item.name)
            return [self.registry.get(name) for name in names if name in self.registry._tools]
        return base

    def _reason_for(
        self,
        definition: ToolDefinition,
        phase: str,
        profile: ProjectProfile | None,
        target: Path,
        availability: ToolAvailability,
    ) -> str:
        if not availability.available:
            return availability.reason or f"{definition.name} is unavailable for {phase}."
        if definition.name == "osv-scanner":
            return "Dependency manifests detected; summarize known vulnerable packages for recon."
        if definition.name in {"pip-audit", "npm-audit", "cargo-audit"}:
            return "Language-specific dependency audit is enabled because a matching manifest exists."
        if definition.name == "gosec":
            return "Go source detected; collect static security findings."
        if definition.name == "bandit":
            return "Python source detected; collect lightweight static findings."
        if definition.name in {"semgrep", "cppcheck", "clang-tidy"}:
            return "Static-analysis signal improves anchor quality for mining."
        if definition.name == "gitleaks":
            return "Secret scan is always useful for recon and mining coverage."
        if definition.name == "rg":
            return "Fast code search provides cheap baseline signal for mining."
        if profile and definition.languages:
            return f"Recommended for detected languages: {', '.join(definition.languages)}."
        return f"Recommended for phase {phase}."

    def _has_python_manifest(self, target: Path) -> bool:
        return any((target / name).exists() for name in ("requirements.txt", "pyproject.toml", "Pipfile"))


class ToolParsers:
    def parse(self, parser: str, stdout: str, stderr: str) -> tuple[Any, list[dict[str, Any]], str]:
        text = stdout.strip() or stderr.strip()
        if parser == "cppcheck":
            findings = self._cppcheck_findings(text)
            return {"errors": findings}, findings, f"findings={len(findings)}"
        if parser == "clang-tidy":
            findings = self._clang_tidy_findings(text)
            return {"findings": findings}, findings, f"findings={len(findings)}"
        if parser in {"semgrep", "gitleaks", "osv-scanner", "bandit", "npm-audit", "pip-audit", "cargo-audit", "gosec", "trivy"}:
            raw = self._json(text)
            findings = self._findings(parser, raw)
            return raw if raw is not None else text[:8000], findings, f"findings={len(findings)}"
        if parser == "text":
            return text[:8000], [], f"bytes={len(text.encode('utf-8', errors='replace'))}"
        raw = self._json(text)
        return raw if raw is not None else text[:8000], [], "parsed=generic"

    def _json(self, text: str) -> Any:
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    def _findings(self, parser: str, raw: Any) -> list[dict[str, Any]]:
        if raw is None:
            return []
        if parser == "semgrep" and isinstance(raw, dict):
            return list(raw.get("results") or [])
        if parser == "gitleaks" and isinstance(raw, list):
            return raw
        if parser == "bandit" and isinstance(raw, dict):
            return list(raw.get("results") or [])
        if parser == "npm-audit" and isinstance(raw, dict):
            vulnerabilities = raw.get("vulnerabilities")
            if isinstance(vulnerabilities, dict):
                return [{"package": name, **value} for name, value in vulnerabilities.items()]
        if parser == "osv-scanner" and isinstance(raw, dict):
            findings: list[dict[str, Any]] = []
            for result in raw.get("results") or []:
                for package in result.get("packages") or []:
                    for vulnerability in package.get("vulnerabilities") or []:
                        findings.append({"package": package.get("package", {}), **vulnerability})
            return findings
        if parser == "pip-audit" and isinstance(raw, dict):
            vulnerabilities = raw.get("vulnerabilities")
            if isinstance(vulnerabilities, list):
                return vulnerabilities
            dependencies = raw.get("dependencies")
            if isinstance(dependencies, list):
                return [{"package": item.get("name"), **vuln} for item in dependencies for vuln in item.get("vulns", [])]
        if parser == "cargo-audit" and isinstance(raw, dict):
            vulnerabilities = raw.get("vulnerabilities")
            if isinstance(vulnerabilities, dict):
                return list(vulnerabilities.get("list") or [])
        if parser == "gosec" and isinstance(raw, dict):
            issues = raw.get("Issues")
            if isinstance(issues, list):
                return issues
        if parser == "trivy" and isinstance(raw, dict):
            findings: list[dict[str, Any]] = []
            for result in raw.get("Results", []):
                target = str(result.get("Target", ""))
                for vuln in result.get("Vulnerabilities", []):
                    findings.append({
                        "package": f"{target}/{vuln.get('PkgName', '')}",
                        "id": vuln.get("VulnerabilityID", ""),
                        "severity": vuln.get("Severity", ""),
                        "title": vuln.get("Title", ""),
                        "installed_version": vuln.get("InstalledVersion", ""),
                        "fixed_version": vuln.get("FixedVersion", ""),
                        "cvss": vuln.get("CVSS", {}),
                        "cwe_ids": vuln.get("CweIDs", []),
                        "references": vuln.get("References", []),
                        "description": vuln.get("Description", ""),
                    })
            return findings
        return []

    def _cppcheck_findings(self, text: str) -> list[dict[str, Any]]:
        if not text.strip():
            return []
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return []
        findings: list[dict[str, Any]] = []
        for error in root.findall(".//error"):
            item = dict(error.attrib)
            location = error.find("location")
            if location is not None:
                item.update({f"location_{key}": value for key, value in location.attrib.items()})
            findings.append(item)
        return findings

    def _clang_tidy_findings(self, text: str) -> list[dict[str, Any]]:
        """Parse clang-tidy text output.

        Standard format:
            /path/to/file.cpp:42:5: warning: message [check-name]
            /path/to/file.cpp:100:10: error: another message [another-check]

        Also handles --export-fixes=- YAML output as fallback.
        """
        if not text.strip():
            return []
        findings: list[dict[str, Any]] = []

        # Try YAML (--export-fixes=-) first
        if text.strip().startswith("---"):
            findings = self._clang_tidy_yaml_findings(text)
            if findings:
                return findings

        # Fallback: regex on standard text output
        pattern = re.compile(
            r"^(.+?):(\d+):(\d+):\s*(warning|error|note|fatal error):\s*(.+?)\s*\[(.+?)\]$",
            re.MULTILINE,
        )
        for match in pattern.finditer(text):
            findings.append({
                "file": match.group(1).strip(),
                "line": int(match.group(2)),
                "column": int(match.group(3)),
                "severity": match.group(4),
                "message": match.group(5).strip(),
                "check": match.group(6).strip(),
            })
        return findings

    def _clang_tidy_yaml_findings(self, text: str) -> list[dict[str, Any]]:
        """Parse clang-tidy --export-fixes=- YAML output."""
        findings: list[dict[str, Any]] = []
        try:
            import yaml  # type: ignore
        except ImportError:
            return []
        try:
            docs = list(yaml.safe_load_all(text))
        except Exception:
            return []
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            diagnostics = doc.get("Diagnostics") or []
            for diag in diagnostics:
                if not isinstance(diag, dict):
                    continue
                findings.append({
                    "file": str(diag.get("FilePath") or ""),
                    "line": 0,  # FileOffset-based line calculation is approximate; use text format for accuracy
                    "column": 0,
                    "severity": str(diag.get("DiagnosticLevel") or "warning"),
                    "message": str(diag.get("Message") or ""),
                    "check": str(diag.get("DiagnosticName") or ""),
                    "offset": int(diag.get("FileOffset") or 0),
                })
        return findings


class ToolCache:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def key_for(self, invocation: ToolInvocation, env_version: str = "") -> str:
        payload = {
            "tool": invocation.tool,
            "command": invocation.command,
            "cwd": str(invocation.cwd.resolve()),
            "context": self._context_hash(invocation.cwd),
            "version": env_version,
        }
        encoded = json.dumps(payload, sort_keys=True).encode("utf-8", errors="replace")
        return hashlib.sha256(encoded).hexdigest()

    def get(self, key: str) -> dict[str, Any] | None:
        path = self.root / f"{key}.json"
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def put(self, key: str, value: dict[str, Any]) -> None:
        path = self.root / f"{key}.json"
        path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")

    def _context_hash(self, cwd: Path) -> str:
        git_head = self._git_head(cwd)
        if git_head:
            return f"git:{git_head}"
        digest = hashlib.sha256()
        for path in sorted(cwd.rglob("*")):
            if not path.is_file() or self._skip_path(path):
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            rel = str(path.relative_to(cwd)).replace("\\", "/")
            digest.update(f"{rel}:{stat.st_size}:{int(stat.st_mtime)}\n".encode("utf-8"))
        return digest.hexdigest()

    def _git_head(self, cwd: Path) -> str:
        try:
            proc = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=str(cwd),
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return ""
        return proc.stdout.strip() if proc.returncode == 0 else ""

    def _skip_path(self, path: Path) -> bool:
        parts = set(path.parts)
        return bool(parts & {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"})


class ArtifactManager:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def write_text(self, tool: str, suffix: str, text: str) -> tuple[str, str]:
        artifact_id = str(uuid.uuid4())
        safe_tool = tool.replace("/", "-").replace("\\", "-")
        path = self.root / safe_tool / f"{artifact_id}.{suffix}"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", errors="replace")
        return artifact_id, str(path)


def run_invocations_parallel(
    invocations: list[ToolInvocation],
    tool_runner: "ToolRunner",
    max_workers: int = 6,
    cancel_callback: Callable[[], bool] | None = None,
) -> list[ToolResult]:
    """Run multiple tool invocations in parallel using a thread pool.

    All tools are independent subprocess calls — ThreadPoolExecutor is ideal because
    the GIL is released during subprocess I/O. Individual tool failures do not abort
    other tools; results are returned in the original invocation order.
    """
    if not invocations:
        return []

    if len(invocations) == 1:
        return [tool_runner.run(invocations[0], cancel_callback=cancel_callback)]

    workers = min(max_workers, len(invocations))
    results: dict[int, ToolResult] = {}

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_index: dict[Any, int] = {}
        for i, invocation in enumerate(invocations):
            future = executor.submit(tool_runner.run, invocation, cancel_callback)
            future_to_index[future] = i

        for future in as_completed(future_to_index):
            idx = future_to_index[future]
            try:
                results[idx] = future.result()
            except Exception as exc:
                # Synthesize an error result so one crash doesn't drop the whole slot
                results[idx] = _synthetic_error_result(invocations[idx], exc)

    return [results[i] for i in range(len(invocations))]


def _synthetic_error_result(invocation: ToolInvocation, exc: Exception) -> ToolResult:
    """Return a ToolResult representing an unhandled execution error."""
    return ToolResult(
        tool=invocation.tool,
        status="error",
        run_id="",
        command=invocation.command,
        summary=f"parallel execution error: {exc}",
        raw={"exception": str(exc)},
        findings=[],
        exit_code=-1,
        duration_ms=0,
        cache_hit=False,
        artifact_records=[],
        started_at=utc_now(),
        finished_at=utc_now(),
    )


class ToolRunner:
    def __init__(
        self,
        settings: Settings,
        registry: ToolRegistry | None = None,
        cache: ToolCache | None = None,
        artifacts: ArtifactManager | None = None,
        sandbox_container: str = "",
    ):
        self.settings = settings
        self.registry = registry or ToolRegistry()
        self.parsers = ToolParsers()
        self.env = self._build_env()
        self.sandbox_container = sandbox_container or getattr(settings, "sandbox_container", "")
        app_root = Path.cwd()
        self.cache = cache or ToolCache(app_root / "data" / "tool-cache")
        self.artifacts = artifacts or ArtifactManager(app_root / "reports" / "tool-artifacts")

    def list_tools(self) -> list[ToolAvailability]:
        return [self.check_tool(tool.name) for tool in self.registry.all()]

    def check_tool(self, name: str) -> ToolAvailability:
        if name in SANDBOX_TOOLS:
            return self._check_sandbox_tool(name)
        availability = self.registry.check_tool(name, self.env)
        availability.execution_location = "backend"
        availability.network_policy = "backend_default"
        return availability

    # ------------------------------------------------------------------
    # Sandbox execution helpers
    # ------------------------------------------------------------------

    def _sandbox_available(self) -> bool:
        """Check whether the sandbox container is running and reachable."""
        if not self.sandbox_container:
            return False
        try:
            proc = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Running}}", self.sandbox_container],
                text=True,
                capture_output=True,
                timeout=5,
                check=False,
            )
            return proc.stdout.strip() == "true"
        except (OSError, subprocess.TimeoutExpired):
            return False

    def _check_sandbox_tool(self, tool: str) -> ToolAvailability:
        """Check whether *tool* is available inside the sandbox container."""
        definition = self.registry.get(tool)
        if not self._sandbox_available():
            return ToolAvailability(
                name=definition.name,
                executable=definition.executable,
                available=False,
                required=definition.required,
                capability=definition.capability,
                reason=f"Sandbox container '{self.sandbox_container}' is not running or docker is unavailable.",
                execution_location="sandbox",
                container=self.sandbox_container,
                network_policy="none",
            )
        try:
            proc = subprocess.run(
                ["docker", "exec", self.sandbox_container, "which", definition.executable],
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return ToolAvailability(
                name=definition.name,
                executable=definition.executable,
                available=False,
                required=definition.required,
                capability=definition.capability,
                reason=f"Cannot check sandbox tool: {exc}",
                execution_location="sandbox",
                container=self.sandbox_container,
                network_policy="none",
            )
        if proc.returncode != 0 or not proc.stdout.strip():
            return ToolAvailability(
                name=definition.name,
                executable=definition.executable,
                available=False,
                required=definition.required,
                capability=definition.capability,
                reason=f"{definition.executable} is not installed in sandbox container '{self.sandbox_container}'.",
                execution_location="sandbox",
                container=self.sandbox_container,
                network_policy="none",
            )
        sandbox_path = proc.stdout.strip()
        try:
            version_proc = subprocess.run(
                ["docker", "exec", self.sandbox_container, sandbox_path, "--version"],
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
            version_line = (version_proc.stdout or version_proc.stderr).strip().splitlines()
            version = version_line[0][:200] if version_line else ""
        except (OSError, subprocess.TimeoutExpired):
            version = ""
        return ToolAvailability(
            name=definition.name,
            executable=definition.executable,
            available=True,
            required=definition.required,
            capability=definition.capability,
            version=version,
            path=sandbox_path,
            execution_location="sandbox",
            container=self.sandbox_container,
            network_policy="none",
        )

    def _run_in_sandbox(
        self,
        invocation: ToolInvocation,
        definition: ToolDefinition,
        run_id: str,
        cancel_callback: Callable[[], bool] | None = None,
    ) -> ToolResult:
        """Execute *invocation* inside the sandbox container via docker exec."""

        if cancel_callback and cancel_callback():
            return ToolResult(
                tool=invocation.tool,
                status="cancelled",
                run_id=run_id,
                command=invocation.command,
                summary=f"{invocation.tool} cancelled before sandbox execution.",
                finished_at=utc_now(),
            )

        # --- availability check ---
        availability = self._check_sandbox_tool(invocation.tool)
        if not availability.available:
            return ToolResult(
                tool=invocation.tool,
                status="blocked",
                run_id=run_id,
                command=invocation.command,
                summary=availability.reason or f"{invocation.tool} is unavailable in sandbox.",
                raw={"availability": asdict_availability(availability), "reason": availability.reason},
                finished_at=utc_now(),
            )

        # --- translate paths for sandbox ---
        sandbox_command = _translate_command_for_sandbox(invocation.command)
        sandbox_cwd = _translate_path_for_sandbox(str(invocation.cwd.resolve()))

        docker_command = [
            "docker", "exec",
            "-w", sandbox_cwd,
            self.sandbox_container,
            *sandbox_command,
        ]

        timeout = invocation.timeout or definition.default_timeout or self.settings.tool_timeout
        cache_key = self.cache.key_for(invocation, availability.version)
        if invocation.cacheable and definition.cacheable:
            cached = self.cache.get(cache_key)
            if cached:
                return self._result_from_cache(invocation, cached, cache_key)

        # --- execute ---
        started_at = utc_now()
        started = time.monotonic()
        proc = subprocess.Popen(
            docker_command,
            cwd=str(invocation.cwd),
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        stdout = ""
        stderr = ""
        cancelled = False
        timed_out = False
        while True:
            if cancel_callback and cancel_callback():
                cancelled = True
                self._terminate(proc)
                break
            elapsed = time.monotonic() - started
            if timeout and elapsed >= timeout:
                timed_out = True
                self._terminate(proc)
                break
            try:
                stdout, stderr = proc.communicate(timeout=0.2)
                break
            except subprocess.TimeoutExpired:
                continue

        if cancelled or timed_out:
            try:
                stdout, stderr = proc.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                self._kill(proc)
                stdout, stderr = proc.communicate()
        duration_ms = int((time.monotonic() - started) * 1000)

        # --- artifacts ---
        stdout_record = self._write_artifact(invocation.tool, "stdout.log", stdout, "tool_stdout", run_id)
        stderr_record = self._write_artifact(invocation.tool, "stderr.log", stderr, "tool_stderr", run_id)
        raw, findings, parse_summary = self.parsers.parse(invocation.parser, stdout, stderr)
        parsed_text = self._serialize_parsed(raw)
        parsed_record = self._write_artifact(invocation.tool, "parsed.json", parsed_text, "tool_parsed", run_id)
        artifact_records = [stdout_record, stderr_record, parsed_record]

        if cancelled:
            return ToolResult(
                tool=invocation.tool, status="cancelled", run_id=run_id,
                command=invocation.command,
                summary=f"{invocation.tool} (sandbox) cancelled.",
                raw=raw, findings=findings, exit_code=proc.returncode,
                duration_ms=duration_ms,
                stdout_artifact_id=stdout_record.id, stderr_artifact_id=stderr_record.id,
                parsed_artifact_id=parsed_record.id,
                cache_key=cache_key, cache_hit=False,
                artifact_records=artifact_records,
                started_at=started_at, finished_at=utc_now(),
            )
        if timed_out:
            return ToolResult(
                tool=invocation.tool, status="timeout", run_id=run_id,
                command=invocation.command,
                summary=f"{invocation.tool} (sandbox) timed out after {timeout}s.",
                raw=raw, findings=findings, exit_code=proc.returncode,
                duration_ms=duration_ms,
                stdout_artifact_id=stdout_record.id, stderr_artifact_id=stderr_record.id,
                parsed_artifact_id=parsed_record.id,
                cache_key=cache_key, cache_hit=False,
                artifact_records=artifact_records,
                started_at=started_at, finished_at=utc_now(),
            )

        status = "ok" if proc.returncode in (0, 1) else "error"
        summary = f"sandbox; exit_code={proc.returncode}; {parse_summary}"
        result = ToolResult(
            tool=invocation.tool, status=status, run_id=run_id,
            command=invocation.command,
            summary=summary, raw=raw, findings=findings,
            exit_code=proc.returncode, duration_ms=duration_ms,
            stdout_artifact_id=stdout_record.id, stderr_artifact_id=stderr_record.id,
            parsed_artifact_id=parsed_record.id,
            cache_key=cache_key, cache_hit=False,
            artifact_records=artifact_records,
            started_at=started_at, finished_at=utc_now(),
        )
        if invocation.cacheable and definition.cacheable:
            self.cache.put(cache_key, {"result": result_to_dict(result)})
        return result

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def run(
        self,
        invocation: ToolInvocation,
        cancel_callback: Callable[[], bool] | None = None,
    ) -> ToolResult:
        definition = self.registry.get(invocation.tool)
        run_id = str(uuid.uuid4())

        # -----------------------------------------------------------------
        # Route C/C++ and multi-language tools through the sandbox container
        # -----------------------------------------------------------------
        if invocation.tool in SANDBOX_TOOLS:
            return self._run_in_sandbox(invocation, definition, run_id, cancel_callback)

        # -----------------------------------------------------------------
        # Local execution path
        # -----------------------------------------------------------------
        availability = self.registry.check_tool(invocation.tool, self.env)
        if cancel_callback and cancel_callback():
            return ToolResult(
                tool=invocation.tool,
                status="cancelled",
                run_id=run_id,
                command=invocation.command,
                summary=f"{invocation.tool} cancelled before execution.",
                raw={"reason": "cancelled_before_start"},
                finished_at=utc_now(),
            )
        if not availability.available:
            return ToolResult(
                tool=invocation.tool,
                status="skipped",
                run_id=run_id,
                command=invocation.command,
                summary=availability.reason or f"{invocation.tool} unavailable",
                raw={"availability": asdict_availability(availability), "reason": availability.reason},
                finished_at=utc_now(),
            )

        command = [availability.path, *invocation.command[1:]]
        timeout = invocation.timeout or definition.default_timeout or self.settings.tool_timeout
        cache_key = self.cache.key_for(invocation, availability.version)
        if invocation.cacheable and definition.cacheable:
            cached = self.cache.get(cache_key)
            if cached:
                return self._result_from_cache(invocation, cached, cache_key)

        started_at = utc_now()
        started = time.monotonic()
        env = self.env.copy()
        env.update(invocation.env)
        proc = subprocess.Popen(
            command,
            cwd=str(invocation.cwd),
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        stdout = ""
        stderr = ""
        cancelled = False
        timed_out = False
        while True:
            if cancel_callback and cancel_callback():
                cancelled = True
                self._terminate(proc)
                break
            elapsed = time.monotonic() - started
            if timeout and elapsed >= timeout:
                timed_out = True
                self._terminate(proc)
                break
            try:
                stdout, stderr = proc.communicate(timeout=0.2)
                break
            except subprocess.TimeoutExpired:
                continue

        if cancelled or timed_out:
            try:
                stdout, stderr = proc.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                self._kill(proc)
                stdout, stderr = proc.communicate()
        duration_ms = int((time.monotonic() - started) * 1000)

        stdout_record = self._write_artifact(invocation.tool, "stdout.log", stdout, "tool_stdout", run_id)
        stderr_record = self._write_artifact(invocation.tool, "stderr.log", stderr, "tool_stderr", run_id)
        raw, findings, parse_summary = self.parsers.parse(invocation.parser, stdout, stderr)
        parsed_text = self._serialize_parsed(raw)
        parsed_record = self._write_artifact(invocation.tool, "parsed.json", parsed_text, "tool_parsed", run_id)
        artifact_records = [stdout_record, stderr_record, parsed_record]

        if cancelled:
            return ToolResult(
                tool=invocation.tool,
                status="cancelled",
                run_id=run_id,
                command=invocation.command,
                summary=f"{invocation.tool} cancelled by callback.",
                raw=raw,
                findings=findings,
                exit_code=proc.returncode,
                duration_ms=duration_ms,
                stdout_artifact_id=stdout_record.id,
                stderr_artifact_id=stderr_record.id,
                parsed_artifact_id=parsed_record.id,
                cache_key=cache_key,
                cache_hit=False,
                artifact_records=artifact_records,
                started_at=started_at,
                finished_at=utc_now(),
            )
        if timed_out:
            return ToolResult(
                tool=invocation.tool,
                status="timeout",
                run_id=run_id,
                command=invocation.command,
                summary=f"{invocation.tool} timed out after {timeout}s.",
                raw=raw,
                findings=findings,
                exit_code=proc.returncode,
                duration_ms=duration_ms,
                stdout_artifact_id=stdout_record.id,
                stderr_artifact_id=stderr_record.id,
                parsed_artifact_id=parsed_record.id,
                cache_key=cache_key,
                cache_hit=False,
                artifact_records=artifact_records,
                started_at=started_at,
                finished_at=utc_now(),
            )

        status = "ok" if proc.returncode in (0, 1) else "error"
        summary = f"exit_code={proc.returncode}; {parse_summary}"
        result = ToolResult(
            tool=invocation.tool,
            status=status,
            run_id=run_id,
            command=invocation.command,
            summary=summary,
            raw=raw,
            findings=findings,
            exit_code=proc.returncode,
            duration_ms=duration_ms,
            stdout_artifact_id=stdout_record.id,
            stderr_artifact_id=stderr_record.id,
            parsed_artifact_id=parsed_record.id,
            cache_key=cache_key,
            cache_hit=False,
            artifact_records=artifact_records,
            started_at=started_at,
            finished_at=utc_now(),
        )
        if invocation.cacheable and definition.cacheable:
            self.cache.put(cache_key, {"result": result_to_dict(result)})
        return result

    def _result_from_cache(self, invocation: ToolInvocation, cached: dict[str, Any], cache_key: str) -> ToolResult:
        data = cached.get("result") or {}
        return ToolResult(
            tool=invocation.tool,
            status=data.get("status", "ok"),
            run_id=data.get("run_id", ""),
            command=data.get("command") or invocation.command,
            summary=f"cache_hit=true; {data.get('summary', '')}",
            raw=data.get("raw"),
            findings=data.get("findings") or [],
            exit_code=data.get("exit_code"),
            duration_ms=data.get("duration_ms"),
            stdout_artifact_id=data.get("stdout_artifact_id", ""),
            stderr_artifact_id=data.get("stderr_artifact_id", ""),
            parsed_artifact_id=data.get("parsed_artifact_id", ""),
            cache_key=cache_key,
            cache_hit=True,
            artifact_records=[artifact_record_from_dict(item) for item in data.get("artifact_records") or []],
            started_at=utc_now(),
            finished_at=utc_now(),
        )

    def _write_artifact(
        self,
        tool: str,
        suffix: str,
        text: str,
        kind: str,
        run_id: str,
    ) -> ArtifactRecord:
        artifact_id, path = self.artifacts.write_text(tool, suffix, text)
        return ArtifactRecord(
            id=artifact_id,
            kind=kind,
            path=path,
            metadata={"tool": tool, "run_id": run_id, "suffix": suffix},
        )

    def _serialize_parsed(self, raw: Any) -> str:
        if isinstance(raw, str):
            return raw
        return json.dumps(raw, ensure_ascii=False, indent=2, default=str)

    def _terminate(self, proc: subprocess.Popen[str]) -> None:
        if proc.poll() is not None:
            return
        try:
            proc.terminate()
        except OSError:
            return

    def _kill(self, proc: subprocess.Popen[str]) -> None:
        if proc.poll() is not None:
            return
        try:
            proc.kill()
        except OSError:
            return

    def _build_env(self) -> dict[str, str]:
        env = os.environ.copy()
        app_root = Path.cwd()
        local_paths = [
            app_root / ".tools" / "bin",
            app_root / ".tools" / "semgrep-venv" / "Scripts",
            app_root / ".tools" / "semgrep-venv" / "bin",
            Path.home() / "go" / "bin",
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
    """Compatibility wrapper over ToolPlanner + ToolRunner for existing imports."""

    def __init__(
        self,
        settings: Settings,
        event_sink: Callable[[str, str, str, dict[str, Any]], None] | None = None,
        tool_runner: ToolRunner | None = None,
        tool_planner: ToolPlanner | None = None,
    ):
        self.tool_runner = tool_runner or ToolRunner(settings)
        self.registry = self.tool_runner.registry
        self.planner = tool_planner or ToolPlanner(
            self.registry,
            self.tool_runner.env,
            availability_provider=self.tool_runner.list_tools,
        )
        self.event_sink = event_sink

    def list_tools(self) -> list[ToolAvailability]:
        return self.planner.list_available_tools()

    def run_all(
        self,
        target: Path,
        profile: ProjectProfile | None = None,
        agent: str = "OrchestratorAgent",
        phase: str = "mine_vulnerabilities",
        cancel_callback: Callable[[], bool] | None = None,
    ) -> list[ToolResult]:
        recommendations = self.planner.recommend_tools(agent, phase, profile, target)
        invocations = self.planner.build_invocations(recommendations, target)
        # Emit tool_start for all tools before parallel execution
        for invocation in invocations:
            self._emit("ToolModule", "tool_start", f"{invocation.tool} started", {"tool": invocation.tool})
        results = run_invocations_parallel(invocations, self.tool_runner, cancel_callback=cancel_callback)
        for result in results:
            self._emit(
                "ToolModule",
                "tool_end",
                f"{result.tool} finished: {result.status}; {result.summary}",
                {
                    "tool": result.tool,
                    "run_id": result.run_id,
                    "status": result.status,
                    "summary": result.summary,
                    "command": result.command,
                    "cache_hit": result.cache_hit,
                    "exit_code": result.exit_code,
                    "duration_ms": result.duration_ms,
                },
            )
        return results

    def run_semgrep(self, target: Path) -> ToolResult:
        return self._run_invocation(self.registry.build_invocation("semgrep", target))

    def run_gitleaks(self, target: Path) -> ToolResult:
        return self._run_invocation(self.registry.build_invocation("gitleaks", target))

    def run_osv_scanner(self, target: Path) -> ToolResult:
        return self._run_invocation(self.registry.build_invocation("osv-scanner", target))

    def run_bandit(self, target: Path) -> ToolResult:
        return self._run_invocation(self.registry.build_invocation("bandit", target))

    def run_npm_audit(self, target: Path) -> ToolResult:
        return self._run_invocation(self.registry.build_invocation("npm-audit", target))

    def _run_invocation(
        self,
        invocation: ToolInvocation,
        cancel_callback: Callable[[], bool] | None = None,
    ) -> ToolResult:
        self._emit("ToolModule", "tool_start", f"{invocation.tool} started", {"tool": invocation.tool})
        result = self.tool_runner.run(invocation, cancel_callback=cancel_callback)
        self._emit(
            "ToolModule",
            "tool_end",
            f"{invocation.tool} finished: {result.status}; {result.summary}",
            {
                "tool": result.tool,
                "run_id": result.run_id,
                "status": result.status,
                "summary": result.summary,
                "command": result.command,
                "cache_hit": result.cache_hit,
                "exit_code": result.exit_code,
                "duration_ms": result.duration_ms,
            },
        )
        return result

    def _emit(self, agent: str, event_type: str, message: str, metadata: dict[str, Any]) -> None:
        if self.event_sink:
            self.event_sink(agent, event_type, message, metadata)


def result_to_dict(result: ToolResult) -> dict[str, Any]:
    return {
        "tool": result.tool,
        "status": result.status,
        "run_id": result.run_id,
        "command": result.command,
        "summary": result.summary,
        "raw": result.raw,
        "findings": result.findings,
        "exit_code": result.exit_code,
        "duration_ms": result.duration_ms,
        "stdout_artifact_id": result.stdout_artifact_id,
        "stderr_artifact_id": result.stderr_artifact_id,
        "parsed_artifact_id": result.parsed_artifact_id,
        "cache_key": result.cache_key,
        "cache_hit": result.cache_hit,
        "artifact_records": [artifact_record_to_dict(item) for item in result.artifact_records],
        "started_at": result.started_at,
        "finished_at": result.finished_at,
    }


def artifact_record_to_dict(record: ArtifactRecord) -> dict[str, Any]:
    return {
        "id": record.id,
        "kind": record.kind,
        "path": record.path,
        "task_id": record.task_id,
        "sha256": record.sha256,
        "size_bytes": record.size_bytes,
        "metadata": record.metadata,
        "created_at": record.created_at,
    }


def artifact_record_from_dict(data: dict[str, Any]) -> ArtifactRecord:
    return ArtifactRecord(
        id=str(data.get("id") or ""),
        kind=str(data.get("kind") or ""),
        path=str(data.get("path") or ""),
        task_id=str(data.get("task_id") or ""),
        sha256=str(data.get("sha256") or ""),
        size_bytes=int(data.get("size_bytes") or 0),
        metadata=dict(data.get("metadata") or {}),
        created_at=str(data.get("created_at") or utc_now()),
    )


def asdict_availability(availability: ToolAvailability) -> dict[str, Any]:
    return {
        "name": availability.name,
        "executable": availability.executable,
        "available": availability.available,
        "required": availability.required,
        "capability": availability.capability,
        "version": availability.version,
        "path": availability.path,
        "reason": availability.reason,
        "execution_location": availability.execution_location,
        "container": availability.container,
        "network_policy": availability.network_policy,
    }
