from __future__ import annotations

from collections import Counter
from pathlib import Path

from ..config import Settings
from ..models import ProjectProfile, normalize_path


LANGUAGE_EXTENSIONS = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".java": "Java",
    ".php": "PHP",
    ".go": "Go",
    ".rb": "Ruby",
    ".cs": "C#",
    ".c": "C",
    ".cpp": "C++",
    ".cc": "C++",
    ".h": "C/C++ Header",
    ".rs": "Rust",
    ".sql": "SQL",
}

IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "vendor",
}

PACKAGE_FILES = {
    "package.json": ["Node.js"],
    "requirements.txt": ["Python"],
    "pyproject.toml": ["Python"],
    "Pipfile": ["Python"],
    "poetry.lock": ["Python"],
    "pom.xml": ["Java", "Maven"],
    "build.gradle": ["Java", "Gradle"],
    "composer.json": ["PHP"],
    "go.mod": ["Go"],
    "Cargo.toml": ["Rust"],
    "Gemfile": ["Ruby"],
    "Dockerfile": ["Docker"],
    "docker-compose.yml": ["Docker Compose"],
}

HIGH_RISK_KEYWORDS = (
    "auth",
    "login",
    "admin",
    "upload",
    "file",
    "download",
    "exec",
    "command",
    "shell",
    "sql",
    "query",
    "db",
    "database",
    "route",
    "controller",
    "api",
    "secret",
    "config",
    ".env",
)

ENTRY_KEYWORDS = (
    "route",
    "routes",
    "controller",
    "views",
    "api",
    "server",
    "app",
    "main",
    "index",
)


class ProjectProfiler:
    def __init__(self, settings: Settings):
        self.settings = settings

    def profile(self, root: Path) -> ProjectProfile:
        root = root.resolve()
        language_counter: Counter[str] = Counter()
        package_files: list[str] = []
        frameworks: set[str] = set()
        entry_points: list[str] = []
        high_risk_files: list[str] = []
        total_files = 0
        scanned_files = 0

        for path in self._iter_files(root):
            total_files += 1
            if scanned_files >= self.settings.max_files:
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size > self.settings.max_file_size:
                continue

            scanned_files += 1
            rel = normalize_path(path, root)
            suffix = path.suffix.lower()
            if suffix in LANGUAGE_EXTENSIONS:
                language_counter[LANGUAGE_EXTENSIONS[suffix]] += 1

            if path.name in PACKAGE_FILES:
                package_files.append(rel)
                frameworks.update(PACKAGE_FILES[path.name])
                frameworks.update(self._detect_frameworks_from_file(path))

            lowered = rel.lower()
            if any(keyword in lowered for keyword in HIGH_RISK_KEYWORDS):
                high_risk_files.append(rel)
            if any(keyword in path.stem.lower() for keyword in ENTRY_KEYWORDS):
                entry_points.append(rel)

        return ProjectProfile(
            root=str(root),
            languages=dict(language_counter.most_common()),
            frameworks=sorted(frameworks),
            package_files=sorted(package_files),
            entry_points=entry_points[:200],
            high_risk_files=high_risk_files[:300],
            total_files=total_files,
            scanned_files=scanned_files,
        )

    def _iter_files(self, root: Path):
        for path in root.rglob("*"):
            if any(part in IGNORED_DIRS for part in path.parts):
                continue
            if path.is_file():
                yield path

    def _detect_frameworks_from_file(self, path: Path) -> set[str]:
        frameworks: set[str] = set()
        try:
            text = path.read_text(encoding="utf-8", errors="ignore").lower()
        except OSError:
            return frameworks

        signatures = {
            "django": "Django",
            "flask": "Flask",
            "fastapi": "FastAPI",
            "express": "Express",
            "koa": "Koa",
            "nestjs": "NestJS",
            "spring-boot": "Spring Boot",
            "laravel": "Laravel",
            "thinkphp": "ThinkPHP",
            "react": "React",
            "vue": "Vue",
        }
        for marker, name in signatures.items():
            if marker in text:
                frameworks.add(name)
        return frameworks
