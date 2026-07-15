from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

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
    ".cxx": "C++",
    ".h": "C/C++ Header",
    ".hpp": "C/C++ Header",
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
    "package-lock.json": ["Node.js"],
    "pnpm-lock.yaml": ["Node.js"],
    "yarn.lock": ["Node.js"],
    "requirements.txt": ["Python"],
    "pyproject.toml": ["Python"],
    "Pipfile": ["Python"],
    "poetry.lock": ["Python"],
    "pom.xml": ["Java", "Maven"],
    "build.gradle": ["Java", "Gradle"],
    "build.gradle.kts": ["Java", "Gradle"],
    "composer.json": ["PHP"],
    "go.mod": ["Go"],
    "Cargo.toml": ["Rust"],
    "Gemfile": ["Ruby"],
    "CMakeLists.txt": ["CMake"],
    "Makefile": ["Make"],
    "configure": ["Autotools"],
    "meson.build": ["Meson"],
    "Dockerfile": ["Docker"],
    "docker-compose.yml": ["Docker Compose"],
}

DEPENDENCY_FILES = {
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "poetry.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "composer.json",
    "go.mod",
    "Cargo.toml",
    "Gemfile",
}

BUILD_FILES = {
    "CMakeLists.txt",
    "compile_commands.json",
    "Makefile",
    "configure",
    "autogen.sh",
    "meson.build",
    "build.ninja",
    "package.json",
    "pyproject.toml",
    "go.mod",
    "Cargo.toml",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "composer.json",
    "Gemfile",
}

CONTAINER_FILES = {"Dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
CI_DIRS = {".github/workflows", ".gitlab-ci.yml", ".circleci", "azure-pipelines.yml", "Jenkinsfile"}
CONFIG_EXTENSIONS = {".yml", ".yaml", ".toml", ".ini", ".conf", ".cfg", ".json", ".env"}

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
    "cli",
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
        dependency_files: list[str] = []
        container_files: list[str] = []
        ci_files: list[str] = []
        config_files: list[str] = []
        build_entries: list[dict[str, Any]] = []
        runtime_entries: list[dict[str, Any]] = []
        test_entries: list[dict[str, Any]] = []
        service_entries: list[dict[str, Any]] = []
        library_entries: list[dict[str, Any]] = []
        env_requirements: list[dict[str, Any]] = []
        total_files = 0
        scanned_files = 0

        files = list(self._iter_files(root))
        for path in files:
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
            if path.name in DEPENDENCY_FILES:
                dependency_files.append(rel)
            if path.name in CONTAINER_FILES:
                container_files.append(rel)
            if self._is_ci_file(rel):
                ci_files.append(rel)
            if path.name in BUILD_FILES:
                build_entries.extend(self._build_entries(path, root))
            if suffix in CONFIG_EXTENSIONS and self._is_config_path(rel):
                config_files.append(rel)

            lowered = rel.lower()
            if any(keyword in lowered for keyword in HIGH_RISK_KEYWORDS):
                high_risk_files.append(rel)
            if any(keyword in path.stem.lower() for keyword in ENTRY_KEYWORDS):
                entry_points.append(rel)

            runtime_entries.extend(self._runtime_entries(path, root))
            test_entries.extend(self._test_entries(path, root))
            service_entries.extend(self._service_entries(path, root))
            library_entries.extend(self._library_entries(path, root))

        env_requirements.extend(self._environment_requirements(root, sorted(set(dependency_files))))
        verification_entries = self._verification_entries(runtime_entries, test_entries, build_entries, service_entries)
        project_type = self._project_type(language_counter, runtime_entries, service_entries, library_entries, build_entries)
        non_runnable_reasons = self._non_runnable_reasons(project_type, runtime_entries, service_entries, build_entries)
        weak_strategies = self._weak_verification_strategies(project_type, non_runnable_reasons, library_entries)

        return ProjectProfile(
            root=str(root),
            languages=dict(language_counter.most_common()),
            frameworks=sorted(frameworks),
            package_files=sorted(set(package_files)),
            entry_points=self._dedupe(entry_points)[:200],
            high_risk_files=self._dedupe(high_risk_files)[:300],
            total_files=total_files,
            scanned_files=scanned_files,
            project_type=project_type,
            build_entries=self._dedupe_entries(build_entries),
            runtime_entries=self._dedupe_entries(runtime_entries),
            test_entries=self._dedupe_entries(test_entries),
            service_entries=self._dedupe_entries(service_entries),
            library_entries=self._dedupe_entries(library_entries),
            dependency_files=sorted(set(dependency_files)),
            container_files=sorted(set(container_files)),
            ci_files=sorted(set(ci_files)),
            config_files=sorted(set(config_files))[:200],
            environment_requirements=self._dedupe_entries(env_requirements),
            verification_entries=self._dedupe_entries(verification_entries),
            non_runnable_reasons=non_runnable_reasons,
            weak_verification_strategies=weak_strategies,
        )

    def _iter_files(self, root: Path):
        for path in root.rglob("*"):
            rel_parts = path.relative_to(root).parts if path != root else ()
            if any(part in IGNORED_DIRS for part in rel_parts):
                continue
            if path.is_file():
                yield path

    def _build_entries(self, path: Path, root: Path) -> list[dict[str, Any]]:
        rel = normalize_path(path, root)
        name = path.name
        entries: list[dict[str, Any]] = []
        if name == "CMakeLists.txt":
            entries.append(self._entry("cmake_build", rel, "cmake -S . -B build -G Ninja && cmake --build build", "CMakeLists.txt detected", 0.95))
            entries.append(self._entry("cmake_sanitizer_build", rel, "cmake -S . -B build-asan -DCMAKE_CXX_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer -g' && cmake --build build-asan", "CMake supports sanitizer-style native builds", 0.75))
            # Record how to generate compile_commands.json
            entries.append(self._entry("compile_commands_generate", rel, "cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON", "compile_commands.json can be generated via CMake", 0.92))
        elif name == "compile_commands.json":
            entries.append(self._entry("compile_database", rel, "clang-tidy -p . && clangd --check=.", "compile_commands.json is present; enables clang-tidy, clangd, and bear", 0.98))
        elif name in {"Makefile", "makefile"}:
            entries.append(self._entry("make_build", rel, "make -j$(nproc)", "Makefile detected", 0.9))
        elif name in {"configure", "autogen.sh"}:
            entries.append(self._entry("autotools_build", rel, f"./{name} && make -j$(nproc)", f"{name} detected", 0.85))
        elif name == "meson.build":
            entries.append(self._entry("meson_build", rel, "meson setup build && ninja -C build", "meson.build detected", 0.9))
        elif name == "package.json":
            scripts = self._package_json_scripts(path)
            for script in ("build", "compile"):
                if script in scripts:
                    entries.append(self._entry("node_build", rel, f"npm run {script}", f"package.json script {script} detected", 0.85))
            if "test" in scripts:
                entries.append(self._entry("node_test", rel, "npm test", "package.json test script detected", 0.85))
        elif name == "pyproject.toml":
            entries.append(self._entry("python_project", rel, "python -m pip install -e .", "pyproject.toml detected", 0.75))
        elif name == "go.mod":
            entries.append(self._entry("go_build", rel, "go build ./...", "go.mod detected", 0.9))
        elif name == "Cargo.toml":
            entries.append(self._entry("rust_build", rel, "cargo build", "Cargo.toml detected", 0.9))
        elif name == "pom.xml":
            entries.append(self._entry("maven_build", rel, "mvn test", "pom.xml detected", 0.85))
        elif name in {"build.gradle", "build.gradle.kts"}:
            entries.append(self._entry("gradle_build", rel, "./gradlew test || gradle test", f"{name} detected", 0.8))
        elif name == "composer.json":
            entries.append(self._entry("php_project", rel, "composer install", "composer.json detected", 0.75))
        elif name == "Gemfile":
            entries.append(self._entry("ruby_project", rel, "bundle install", "Gemfile detected", 0.75))
        return entries

    def _runtime_entries(self, path: Path, root: Path) -> list[dict[str, Any]]:
        rel = normalize_path(path, root)
        name = path.name.lower()
        suffix = path.suffix.lower()
        entries: list[dict[str, Any]] = []
        text = self._safe_read(path, limit=120_000)
        if suffix == ".py" and self._looks_python_entry(text, name):
            entries.append(self._entry("python_cli_or_service", rel, f"python {rel}", "Python entrypoint pattern detected", 0.75))
        if suffix in {".js", ".ts"} and self._looks_node_entry(text, name):
            command = f"node {rel}" if suffix == ".js" else f"npm exec ts-node {rel}"
            entries.append(self._entry("node_cli_or_service", rel, command, "Node entrypoint pattern detected", 0.75))
        if suffix in {".c", ".cpp", ".cc", ".cxx"} and re.search(r"\bint\s+main\s*\(", text):
            entries.append(self._entry("native_cli_main", rel, "", "C/C++ main function detected", 0.85))
        if suffix == ".go" and re.search(r"package\s+main", text):
            entries.append(self._entry("go_cli_or_service", rel, "go run .", "Go package main detected", 0.8))
        if suffix == ".rs" and rel.endswith("src/main.rs"):
            entries.append(self._entry("rust_cli_or_service", rel, "cargo run", "Rust src/main.rs detected", 0.85))
        if path.name == "package.json":
            scripts = self._package_json_scripts(path)
            for script in ("start", "dev", "serve"):
                if script in scripts:
                    entries.append(self._entry("node_script", rel, f"npm run {script}", f"package.json script {script} detected", 0.85))
        return entries

    def _test_entries(self, path: Path, root: Path) -> list[dict[str, Any]]:
        rel = normalize_path(path, root)
        lowered = rel.lower()
        entries: list[dict[str, Any]] = []
        if path.name == "package.json":
            scripts = self._package_json_scripts(path)
            if "test" in scripts:
                entries.append(self._entry("node_test", rel, "npm test", "package.json test script detected", 0.9))
        if path.name == "pyproject.toml":
            entries.append(self._entry("python_test", rel, "python -m pytest", "pyproject.toml detected; pytest is a common test entry", 0.65))
        if path.name == "go.mod":
            entries.append(self._entry("go_test", rel, "go test ./...", "go.mod detected", 0.9))
        if path.name == "Cargo.toml":
            entries.append(self._entry("rust_test", rel, "cargo test", "Cargo.toml detected", 0.9))
        if path.name == "pom.xml":
            entries.append(self._entry("maven_test", rel, "mvn test", "pom.xml detected", 0.85))
        if path.name in {"build.gradle", "build.gradle.kts"}:
            entries.append(self._entry("gradle_test", rel, "./gradlew test || gradle test", f"{path.name} detected", 0.8))
        if lowered.startswith("tests/") or "/tests/" in lowered or path.name.startswith("test_") or path.name.endswith("_test.py"):
            entries.append(self._entry("test_file", rel, "", "test file path detected", 0.75))
        return entries

    def _service_entries(self, path: Path, root: Path) -> list[dict[str, Any]]:
        rel = normalize_path(path, root)
        text = self._safe_read(path, limit=120_000)
        entries: list[dict[str, Any]] = []
        markers = {
            "fastapi(": "FastAPI service",
            "flask(": "Flask service",
            "express(": "Express service",
            "koa(": "Koa service",
            "@springbootapplication": "Spring Boot service",
            "http.listenandserve": "Go HTTP service",
        }
        lowered = text.lower()
        for marker, evidence in markers.items():
            if marker in lowered:
                entries.append(self._entry("web_service", rel, "", evidence, 0.78))
        return entries

    def _library_entries(self, path: Path, root: Path) -> list[dict[str, Any]]:
        rel = normalize_path(path, root)
        entries: list[dict[str, Any]] = []
        if path.name == "__init__.py":
            entries.append(self._entry("python_package", rel, "", "Python package init detected", 0.6))
        if rel.endswith("src/lib.rs"):
            entries.append(self._entry("rust_library", rel, "cargo test", "Rust library entry detected", 0.85))
        if path.name == "go.mod" and not (root / "main.go").exists():
            entries.append(self._entry("go_module", rel, "go test ./...", "Go module detected", 0.65))
        if path.name == "composer.json":
            entries.append(self._entry("php_package", rel, "composer test", "composer package detected", 0.65))
        return entries

    def _environment_requirements(self, root: Path, dependency_files: list[str]) -> list[dict[str, Any]]:
        requirements: list[dict[str, Any]] = []
        for rel in dependency_files:
            name = Path(rel).name
            if name in {"requirements.txt", "pyproject.toml", "Pipfile", "poetry.lock"}:
                requirements.append(self._entry("python_runtime", rel, "python -m pip install -r requirements.txt", "Python dependency file detected", 0.75))
            elif name in {"package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"}:
                requirements.append(self._entry("node_runtime", rel, "npm install", "Node dependency file detected", 0.75))
            elif name == "go.mod":
                requirements.append(self._entry("go_runtime", rel, "go mod download", "go.mod detected", 0.8))
            elif name == "Cargo.toml":
                requirements.append(self._entry("rust_runtime", rel, "cargo fetch", "Cargo.toml detected", 0.8))
            elif name in {"pom.xml", "build.gradle", "build.gradle.kts"}:
                requirements.append(self._entry("java_runtime", rel, "", "Java build file detected", 0.75))
            elif name == "composer.json":
                requirements.append(self._entry("php_runtime", rel, "composer install", "composer.json detected", 0.7))
            elif name == "Gemfile":
                requirements.append(self._entry("ruby_runtime", rel, "bundle install", "Gemfile detected", 0.7))
        if any((root / name).exists() for name in ("CMakeLists.txt", "Makefile", "configure", "meson.build")):
            requirements.append(self._entry("native_build_toolchain", "", "cmake/ninja/make/gcc/clang", "Native build files detected", 0.8))
        return requirements

    def _verification_entries(
        self,
        runtime_entries: list[dict[str, Any]],
        test_entries: list[dict[str, Any]],
        build_entries: list[dict[str, Any]],
        service_entries: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        for entry in test_entries[:20]:
            entries.append({**entry, "kind": f"verify_{entry['kind']}", "evidence": f"Test entry: {entry['evidence']}"})
        for entry in runtime_entries[:20]:
            entries.append({**entry, "kind": f"verify_{entry['kind']}", "evidence": f"Runtime entry: {entry['evidence']}"})
        for entry in service_entries[:20]:
            entries.append({**entry, "kind": "verify_http_service", "evidence": f"Service entry: {entry['evidence']}"})
        for entry in build_entries[:20]:
            if "sanitizer" in entry["kind"] or "native" in entry["kind"] or "cmake" in entry["kind"]:
                entries.append({**entry, "kind": f"verify_{entry['kind']}", "evidence": f"Build entry: {entry['evidence']}"})
        return entries

    def _project_type(
        self,
        languages: Counter[str],
        runtime_entries: list[dict[str, Any]],
        service_entries: list[dict[str, Any]],
        library_entries: list[dict[str, Any]],
        build_entries: list[dict[str, Any]],
    ) -> str:
        if service_entries:
            return "web_service"
        if any(entry["kind"].endswith("main") or "cli" in entry["kind"] for entry in runtime_entries):
            return "cli"
        if library_entries and not runtime_entries:
            return "library"
        if languages and build_entries:
            return "mixed" if len(languages) > 1 else "library"
        return "unknown"

    def _non_runnable_reasons(
        self,
        project_type: str,
        runtime_entries: list[dict[str, Any]],
        service_entries: list[dict[str, Any]],
        build_entries: list[dict[str, Any]],
    ) -> list[str]:
        reasons: list[str] = []
        if project_type in {"library", "unknown"} and not runtime_entries and not service_entries:
            reasons.append("no_direct_runtime_entry_detected")
        if project_type == "library":
            reasons.append("library_requires_harness_or_host_application")
        if build_entries and not runtime_entries and not service_entries:
            reasons.append("build_detected_but_no_run_command_confirmed")
        return sorted(set(reasons))

    def _weak_verification_strategies(
        self,
        project_type: str,
        non_runnable_reasons: list[str],
        library_entries: list[dict[str, Any]],
    ) -> list[str]:
        strategies: list[str] = []
        if non_runnable_reasons:
            strategies.extend(["static_reachability", "local_harness", "blocked_with_evidence"])
        if project_type == "library" or library_entries:
            strategies.extend(["library_harness", "mock_runtime"])
        if not strategies:
            strategies.append("normal_runtime_or_test_verification")
        return sorted(set(strategies))

    def _detect_frameworks_from_file(self, path: Path) -> set[str]:
        frameworks: set[str] = set()
        text = self._safe_read(path).lower()
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

    def _package_json_scripts(self, path: Path) -> dict[str, str]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        scripts = data.get("scripts")
        return scripts if isinstance(scripts, dict) else {}

    def _looks_python_entry(self, text: str, name: str) -> bool:
        lowered = text.lower()
        return (
            name in {"app.py", "main.py", "server.py", "cli.py", "manage.py"}
            or "if __name__ == \"__main__\"" in text
            or "uvicorn.run" in lowered
            or ".run(" in lowered and ("flask" in lowered or "fastapi" in lowered)
        )

    def _looks_node_entry(self, text: str, name: str) -> bool:
        lowered = text.lower()
        return (
            name in {"app.js", "server.js", "index.js", "main.js", "cli.js"}
            or "listen(" in lowered
            or "commander" in lowered
            or "process.argv" in lowered
        )

    def _is_ci_file(self, rel: str) -> bool:
        lowered = rel.lower()
        return any(lowered.startswith(marker) or lowered == marker for marker in CI_DIRS)

    def _is_config_path(self, rel: str) -> bool:
        lowered = rel.lower()
        return any(part in lowered for part in ("config", "settings", ".env", "compose", ".github"))

    def _entry(self, kind: str, file_path: str, command: str, evidence: str, confidence: float) -> dict[str, Any]:
        return {
            "kind": kind,
            "file": file_path,
            "command": command,
            "evidence": evidence,
            "confidence": confidence,
        }

    def _dedupe(self, values: list[str]) -> list[str]:
        return list(dict.fromkeys(values))

    def _dedupe_entries(self, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen: set[tuple[str, str, str]] = set()
        output: list[dict[str, Any]] = []
        for entry in entries:
            key = (str(entry.get("kind", "")), str(entry.get("file", "")), str(entry.get("command", "")))
            if key in seen:
                continue
            seen.add(key)
            output.append(entry)
        return output[:200]

    def _safe_read(self, path: Path, limit: int = 80_000) -> str:
        try:
            data = path.read_bytes()[:limit]
        except OSError:
            return ""
        return data.decode("utf-8", errors="ignore")
