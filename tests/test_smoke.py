import sqlite3
import json
import subprocess
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from agentic_code_audit.audit_budget import AuditBudget
from agentic_code_audit.agents.mining import (
    CandidateGenerator,
    ClueAggregator,
    coerce_str_list,
    DangerousFunctionLocator,
    MiningResult,
    SliceAnalyzer,
    VulnerabilityClassifier,
)
from agentic_code_audit.agents.mining_director import CodeExplorationTools, MiningDirector, MiningStrategy, ToolSelection
from agentic_code_audit.agents.profiler import ProjectProfiler
from agentic_code_audit.agents.recon import ReconAgent
from agentic_code_audit.agents.verification import (
    BuildDecision,
    BuildManager,
    CheckerOutcome,
    CommandInjectionChecker,
    DependencyChecker,
    DynamicVerificationPlan,
    DynamicPlanner,
    EnvironmentProfile,
    EnvironmentManager,
    EvidenceChecker,
    ExploitAgent,
    HarnessPlan,
    MemorySafetyChecker,
    PathTraversalChecker,
    PocAnalysis,
    PocGenerator,
    PocPlan,
    RuntimeManager,
    SandboxExecutor,
    SQLInjectionChecker,
    StaticVerifier,
    VerificationAgent,
    VerificationPlanner,
)
from agentic_code_audit.cli import main as cli_main
from agentic_code_audit.config import Settings
from agentic_code_audit.inputs import TargetResolver
from agentic_code_audit.models import (
    ArtifactRecord,
    AuditReport,
    DangerousFunction,
    Finding,
    FunctionSummary,
    InputSource,
    ProgramSlice,
    ProjectProfile,
    SemanticIndex,
    ToolResult,
    VerificationResult,
    VulnerabilityCandidate,
)
from agentic_code_audit.rules import RulesLoader
from agentic_code_audit.reporting import ReportWriter
from agentic_code_audit.store import AuditStore
from agentic_code_audit.tools.runner import (
    ArtifactManager,
    ToolCache,
    ToolAvailability,
    ToolDefinition,
    ToolInvocation,
    ToolParsers,
    ToolPlanner,
    ToolRegistry,
    ToolRunner,
)
from agentic_code_audit.mining_debug import generate_mining_debug
from agentic_code_audit.pipeline import AuditPipeline


class FakeLLM:
    enabled = True

    def chat(self, *_args, **_kwargs):
        return type("Resp", (), {"ok": True, "content": "娴嬭瘯 LLM 杈撳嚭", "error": ""})()


def make_settings() -> Settings:
    return Settings(
        llm_provider="deepseek",
        llm_api_key="test",
        llm_base_url="https://api.deepseek.com",
        llm_model="deepseek-v4-pro",
        max_files=1000,
        max_file_size=100000,
        tool_timeout=30,
        auto_build_native=False,
    )


def test_runtime_llm_settings_override_environment(tmp_path: Path, monkeypatch):
    from agentic_code_audit.config import save_runtime_llm_settings

    monkeypatch.setenv("LLM_MODEL", "environment-model")
    save_runtime_llm_settings(
        tmp_path,
        {
            "LLM_PROVIDER": "openai-compatible",
            "LLM_API_KEY": "runtime-key",
            "LLM_BASE_URL": "https://example.test/v1",
            "LLM_MODEL": "runtime-model",
        },
    )

    settings = Settings.load(tmp_path)

    assert settings.llm_api_key == "runtime-key"
    assert settings.llm_model == "runtime-model"
    assert settings.llm_base_url == "https://example.test/v1"


def test_llm_settings_api_masks_key_and_tests_connection(tmp_path: Path, monkeypatch):
    import agentic_code_audit.server as server_module

    monkeypatch.setattr(server_module, "APP_ROOT", tmp_path)
    monkeypatch.setattr(server_module, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(
        server_module.DeepSeekClient,
        "chat",
        lambda *_args, **_kwargs: type("Response", (), {"ok": True, "content": "OK", "error": ""})(),
    )
    client = TestClient(server_module.app)
    payload = {
        "provider": "openai-compatible",
        "base_url": "https://example.test/v1/chat/completions",
        "model": "test-model",
        "api_key": "secret-value",
    }

    saved = client.put("/api/settings/llm", json=payload)
    tested = client.post("/api/settings/llm/test", json={**payload, "api_key": ""})

    assert saved.status_code == 200
    assert saved.json()["base_url"] == "https://example.test/v1"
    assert saved.json()["api_key_hint"] == "••••alue"
    assert "secret-value" not in saved.text
    assert tested.status_code == 200
    assert tested.json()["ok"] is True
    assert tested.json()["message"] == "OK"


def test_system_shutdown_requires_enablement_and_confirmation(monkeypatch):
    import agentic_code_audit.server as server_module

    client = TestClient(server_module.app)
    monkeypatch.delenv("AUDIT_ALLOW_SYSTEM_SHUTDOWN", raising=False)
    disabled = client.post("/api/system/shutdown", json={"confirmation": "SHUTDOWN"})
    monkeypatch.setenv("AUDIT_ALLOW_SYSTEM_SHUTDOWN", "1")
    invalid = client.post("/api/system/shutdown", json={"confirmation": "no"})

    assert disabled.status_code == 403
    assert invalid.status_code == 400


def test_system_shutdown_cancels_tasks_and_schedules_compose_stop(tmp_path: Path, monkeypatch):
    import agentic_code_audit.server as server_module

    store = AuditStore(tmp_path / "shutdown.sqlite3")
    task_id = store.create_task("examples/vulnerable-python", "standard", "test-model", "", False)
    assert store.mark_running(task_id, "Orchestrator", "task_started")
    targets = [("a" * 12, "frontend"), ("b" * 12, "sandbox"), ("c" * 12, "backend")]
    launched: list[list[tuple[str, str]]] = []
    monkeypatch.setenv("AUDIT_ALLOW_SYSTEM_SHUTDOWN", "1")
    monkeypatch.setattr(server_module, "STORE", store)
    monkeypatch.setattr(server_module, "_compose_shutdown_targets", lambda: targets)
    monkeypatch.setattr(server_module, "_launch_compose_shutdown", lambda value: launched.append(value))
    client = TestClient(server_module.app)

    response = client.post("/api/system/shutdown", json={"confirmation": "SHUTDOWN"})

    assert response.status_code == 202
    assert response.json()["services"] == ["frontend", "sandbox", "backend"]
    assert response.json()["running_tasks_cancelled"] == 1
    assert store.get_task(task_id)["status"] == "cancelled"
    assert launched == [targets]


def test_cli_rejects_missing_deepseek_key(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "")
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    code = cli_main(["audit", "examples/vulnerable-python", "--project-dir", str(tmp_path)])
    assert code == 2


def test_store_task_state_machine_and_events(tmp_path: Path):
    store = AuditStore(tmp_path / "audit.sqlite3")
    task_id = store.create_task(
        "https://github.com/example/project.git",
        "full",
        "deepseek-v4-pro",
        "",
        False,
        llm_provider="deepseek",
    )

    created = store.get_task(task_id)
    assert created is not None
    assert created["status"] == "queued"
    assert created["target_type"] == "github"
    assert created["llm_provider"] == "deepseek"
    assert created["llm_model"] == "deepseek-v4-pro"

    assert store.mark_running(task_id, "Orchestrator", "task_started")
    store.add_event(
        task_id,
        "ReconAgent",
        "stage_start",
        "profile",
        {"progress_done": 1, "progress_total": 8},
        phase="profile_project",
    )
    running = store.get_task(task_id)
    assert running is not None
    assert running["status"] == "running"
    assert running["current_agent"] == "ReconAgent"
    assert running["current_phase"] == "profile_project"
    assert running["progress_done"] == 1
    assert running["progress_total"] == 8

    events = store.get_events(task_id)
    assert events[-1]["phase"] == "profile_project"
    assert events[-1]["metadata"]["progress_total"] == 8

    store.mark_completed(task_id)
    assert not store.mark_running(task_id, "Orchestrator", "restart")
    completed = store.get_task(task_id)
    assert completed is not None
    assert completed["status"] == "completed"


def test_store_migrates_existing_sqlite_schema(tmp_path: Path):
    db_path = tmp_path / "old.sqlite3"
    with sqlite3.connect(db_path) as conn:
        conn.executescript(
            """
            create table tasks (
              id text primary key,
              target text not null,
              mode text not null,
              model text not null,
              status text not null,
              runtime_url text default '',
              enable_native_build integer default 0,
              report_dir text default '',
              json_report text default '',
              markdown_report text default '',
              error text default '',
              created_at text not null,
              started_at text,
              finished_at text
            );
            create table agent_events (
              id integer primary key autoincrement,
              task_id text not null,
              sequence integer not null,
              agent text not null,
              event_type text not null,
              message text not null,
              metadata text not null,
              created_at text not null
            );
            """
        )

    store = AuditStore(db_path)
    task_id = store.create_task("examples/vulnerable-python", "full", "deepseek-v4-pro", "", False)
    store.add_event(task_id, "InputAgent", "progress", "ready", phase="resolve_target")
    task = store.get_task(task_id)
    events = store.get_events(task_id)

    assert task is not None
    assert task["llm_model"] == "deepseek-v4-pro"
    assert task["current_phase"] == "resolve_target"
    assert events[-1]["phase"] == "resolve_target"


def test_store_saves_project_profile(tmp_path: Path):
    store = AuditStore(tmp_path / "audit.sqlite3")
    task_id = store.create_task("examples/vulnerable-python", "full", "deepseek-v4-pro", "", False)
    profile = ProjectProfile(
        root="examples/vulnerable-python",
        languages={"Python": 1},
        project_type="web_service",
        verification_entries=[{"kind": "verify_python_cli", "file": "app.py", "command": "python app.py"}],
    )

    store.save_project_profile(task_id, profile)
    saved = store.get_project_profile(task_id)

    assert saved is not None
    assert saved["project_type"] == "web_service"
    assert saved["verification_entries"][0]["file"] == "app.py"


def test_store_delete_task_removes_history_records_and_files(tmp_path: Path):
    store = AuditStore(tmp_path / "audit.sqlite3")
    task_id = store.create_task("examples/vulnerable-python", "full", "deepseek-v4-pro", "", False)
    report_dir = tmp_path / "reports" / task_id
    report_dir.mkdir(parents=True)
    json_report = report_dir / "audit-report.json"
    markdown_report = report_dir / "audit-report.md"
    tool_artifact = tmp_path / "tool-artifact.log"
    json_report.write_text("{}", encoding="utf-8")
    markdown_report.write_text("# report\n", encoding="utf-8")
    tool_artifact.write_text("tool output\n", encoding="utf-8")
    profile = ProjectProfile(root="examples/vulnerable-python")
    finding = Finding(
        id="finding-1",
        vulnerability_type="command_injection",
        severity="high",
        title="finding",
        description="finding",
        file_path="app.py",
    )
    report = AuditReport(
        input_source=InputSource(original="examples/vulnerable-python", kind="local", local_path="examples/vulnerable-python"),
        target="examples/vulnerable-python",
        created_at="2026-01-01T00:00:00+00:00",
        profile=profile,
        semantic_index=SemanticIndex(),
        tool_results=[
            ToolResult(
                tool="semgrep",
                status="ok",
                run_id="run-1",
                artifact_records=[
                    ArtifactRecord(
                        id="artifact-1",
                        kind="tool_stdout",
                        path=str(tool_artifact),
                        metadata={"name": "tool-artifact.log"},
                    )
                ],
            )
        ],
        dangerous_functions=[],
        program_slices=[],
        candidates=[],
        findings=[finding],
        verification_results=[],
    )
    store.add_event(task_id, "System", "test", "event")
    store.save_report(task_id, report, json_report, markdown_report)

    assert store.delete_task(task_id)

    assert store.get_task(task_id) is None
    assert store.list_findings(task_id) == []
    assert store.get_events(task_id) == []
    assert not report_dir.exists()
    assert not tool_artifact.exists()
    with store.connect() as conn:
        assert conn.execute("select count(*) from artifacts where task_id=?", (task_id,)).fetchone()[0] == 0


def test_tool_registry_reports_required_and_optional_tools():
    registry = ToolRegistry()
    names = {tool.name: tool for tool in registry.all()}

    assert names["rg"].required is True
    assert names["semgrep"].required is True
    assert names["gitleaks"].capability == "secret-scan"
    assert names["cppcheck"].required is False


def test_stage2_tool_installation_files_cover_core_tools():
    script = Path("scripts/install_tools.ps1").read_text(encoding="utf-8")
    dockerfile = Path("docker/sandbox/Dockerfile").read_text(encoding="utf-8")

    assert "ripgrep" in script
    assert "rg.exe" in script
    assert "npm --version" in script
    assert "ripgrep" in dockerfile
    assert "nodejs" in dockerfile
    assert "npm" in dockerfile


def test_tool_registry_recommends_language_specific_tools(tmp_path: Path):
    project = tmp_path / "mixed"
    project.mkdir()
    (project / "requirements.txt").write_text("flask\n", encoding="utf-8")
    (project / "package.json").write_text(json_dump({"scripts": {"test": "vitest"}}), encoding="utf-8")
    (project / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.16)\n", encoding="utf-8")
    (project / "main.cpp").write_text("int main(){return 0;}\n", encoding="utf-8")
    (project / "main.go").write_text("package main\nfunc main(){}\n", encoding="utf-8")
    (project / "Cargo.toml").write_text("[package]\nname='demo'\nversion='0.1.0'\n", encoding="utf-8")

    names = {tool.name for tool in ToolRegistry().recommend_for_project(project)}

    assert {"rg", "semgrep", "gitleaks", "osv-scanner", "bandit", "pip-audit", "npm-audit", "cppcheck", "gosec", "cargo-audit"} <= names


def test_tool_planner_recommends_phase_specific_tools(tmp_path: Path):
    project = tmp_path / "mixed"
    project.mkdir()
    (project / "requirements.txt").write_text("flask\n", encoding="utf-8")
    (project / "package.json").write_text(json_dump({"name": "demo"}), encoding="utf-8")
    (project / "main.cpp").write_text("int main(){return 0;}\n", encoding="utf-8")
    (project / "main.go").write_text("package main\nfunc main(){}\n", encoding="utf-8")
    profile = ProjectProfile(root=str(project), languages={"Python": 1, "JavaScript": 1, "C++": 1, "Go": 1})

    runner = ToolRunner(make_settings())
    planner = ToolPlanner(runner.registry, runner.env)
    recon = {item.name for item in planner.recommend_tools("ReconAgent", "profile_project", profile, project)}
    mining = {item.name for item in planner.recommend_tools("VulnerabilityMiningAgent", "mine_vulnerabilities", profile, project)}

    assert {"osv-scanner", "pip-audit", "npm-audit", "gosec"} <= recon
    assert {"rg", "semgrep", "gitleaks", "pip-audit", "npm-audit", "cppcheck", "gosec"} <= mining


def test_tool_parsers_extract_semgrep_findings():
    raw = {
        "results": [
            {
                "check_id": "python.lang.security.audit.subprocess-shell-true",
                "path": "app.py",
                "start": {"line": 10},
            }
        ]
    }
    parsed, findings, summary = ToolParsers().parse("semgrep", json_dump(raw), "")

    assert parsed["results"][0]["path"] == "app.py"
    assert len(findings) == 1
    assert summary == "findings=1"


def test_tool_parsers_extract_stage4_findings():
    parsers = ToolParsers()
    cpp_raw, cpp_findings, _ = parsers.parse(
        "cppcheck",
        "",
        """<?xml version=\"1.0\" encoding=\"UTF-8\"?><results><errors><error id=\"bufferAccessOutOfBounds\" severity=\"error\" msg=\"out of bounds\"><location file=\"main.cpp\" line=\"7\"/></error></errors></results>""",
    )
    pip_raw, pip_findings, _ = parsers.parse(
        "pip-audit",
        json_dump({"dependencies": [{"name": "demo", "vulns": [{"id": "PYSEC-1"}]}]}),
        "",
    )
    cargo_raw, cargo_findings, _ = parsers.parse(
        "cargo-audit",
        json_dump({"vulnerabilities": {"list": [{"advisory": {"id": "RUSTSEC-1"}}]}}),
        "",
    )
    gosec_raw, gosec_findings, _ = parsers.parse(
        "gosec",
        json_dump({"Issues": [{"rule_id": "G204", "file": "main.go", "line": "5"}]}),
        "",
    )

    assert cpp_raw["errors"][0]["id"] == "bufferAccessOutOfBounds"
    assert cpp_findings[0]["location_file"] == "main.cpp"
    assert pip_findings[0]["package"] == "demo"
    assert cargo_findings[0]["advisory"]["id"] == "RUSTSEC-1"
    assert gosec_findings[0]["rule_id"] == "G204"


def test_tool_runner_executes_and_caches_tool_output(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="python-json",
            executable=sys.executable,
            capability="test-json",
            parser="generic",
            version_args=("--version",),
        )
    )
    settings = make_settings()
    runner = ToolRunner(
        settings,
        registry=registry,
        cache=ToolCache(tmp_path / "cache"),
        artifacts=ArtifactManager(tmp_path / "artifacts"),
    )
    invocation = ToolInvocation(
        tool="python-json",
        command=[sys.executable, "-c", "import json; print(json.dumps({'ok': True}))"],
        cwd=project,
        parser="generic",
    )

    first = runner.run(invocation)
    second = runner.run(invocation)

    assert first.status == "ok"
    assert first.raw == {"ok": True}
    assert first.stdout_artifact_id
    assert first.parsed_artifact_id
    assert len(first.artifact_records) == 3
    assert second.cache_hit is True
    assert second.parsed_artifact_id == first.parsed_artifact_id


def test_tool_runner_skips_missing_tool_with_reason(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="missing-tool",
            executable="definitely-missing-binary-12345",
            capability="test-missing",
        )
    )
    runner = ToolRunner(
        make_settings(),
        registry=registry,
        cache=ToolCache(tmp_path / "cache"),
        artifacts=ArtifactManager(tmp_path / "artifacts"),
    )
    result = runner.run(ToolInvocation(tool="missing-tool", command=["definitely-missing-binary-12345"], cwd=project))

    assert result.status == "skipped"
    assert "not in PATH" in result.summary


def test_tool_runner_cancellation_terminates_process(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="sleepy-python",
            executable=sys.executable,
            capability="test-cancel",
            parser="text",
        )
    )
    runner = ToolRunner(
        make_settings(),
        registry=registry,
        cache=ToolCache(tmp_path / "cache"),
        artifacts=ArtifactManager(tmp_path / "artifacts"),
    )
    invocation = ToolInvocation(
        tool="sleepy-python",
        command=[sys.executable, "-c", "import time; time.sleep(5); print('done')"],
        cwd=project,
        parser="text",
        cacheable=False,
    )
    state = {"calls": 0}

    def cancel() -> bool:
        state["calls"] += 1
        return state["calls"] >= 2

    result = runner.run(invocation, cancel_callback=cancel)

    assert result.status == "cancelled"
    assert result.stdout_artifact_id
    assert result.parsed_artifact_id


def json_dump(value) -> str:
    import json

    return json.dumps(value)


def test_recon_profiles_python_project_with_runtime_and_verification_entries(tmp_path: Path):
    target = tmp_path / "python-app"
    target.mkdir()
    (target / "requirements.txt").write_text("fastapi\npytest\n", encoding="utf-8")
    (target / "app.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\nif __name__ == \"__main__\":\n    import uvicorn; uvicorn.run(app)\n",
        encoding="utf-8",
    )
    (target / "tests").mkdir()
    (target / "tests" / "test_app.py").write_text("def test_ok(): assert True\n", encoding="utf-8")

    profile = ProjectProfiler(make_settings()).profile(target)

    assert profile.languages["Python"] >= 2
    assert profile.project_type in {"web_service", "cli"}
    assert any(entry["kind"] == "python_cli_or_service" for entry in profile.runtime_entries)
    assert any(entry["kind"].startswith("verify_") for entry in profile.verification_entries)
    assert "requirements.txt" in profile.dependency_files


def test_recon_profiles_node_scripts(tmp_path: Path):
    target = tmp_path / "node-app"
    target.mkdir()
    (target / "package.json").write_text(
        json_dump(
            {
                "scripts": {"start": "node server.js", "test": "vitest", "build": "vite build"},
                "dependencies": {"express": "^4.0.0"},
            }
        ),
        encoding="utf-8",
    )
    (target / "server.js").write_text("const express = require('express'); express().listen(3000)\n", encoding="utf-8")

    profile = ProjectProfiler(make_settings()).profile(target)

    assert "Node.js" in profile.frameworks
    assert any(entry["command"] == "npm run build" for entry in profile.build_entries)
    assert any(entry["command"] == "npm run start" for entry in profile.runtime_entries)
    assert any(entry["command"] == "npm test" for entry in profile.test_entries)


def test_recon_profiles_cpp_build_and_harness_strategy(tmp_path: Path):
    target = tmp_path / "native"
    target.mkdir()
    (target / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.16)\nadd_executable(app main.cpp)\n",
        encoding="utf-8",
    )
    (target / "main.cpp").write_text("int main(int argc, char **argv) { return argc > 1 ? 0 : 1; }\n", encoding="utf-8")

    profile = ProjectProfiler(make_settings()).profile(target)

    assert profile.languages["C++"] == 1
    assert any(entry["kind"] == "cmake_build" for entry in profile.build_entries)
    assert any(entry["kind"] == "native_cli_main" for entry in profile.runtime_entries)
    assert any("sanitizer" in entry["kind"] for entry in profile.verification_entries)


def test_recon_profiles_library_with_weak_verification_strategy(tmp_path: Path):
    target = tmp_path / "library"
    (target / "pkg").mkdir(parents=True)
    (target / "pkg" / "__init__.py").write_text("def parse(data): return data\n", encoding="utf-8")
    (target / "pyproject.toml").write_text("[project]\nname='library'\n", encoding="utf-8")

    profile = ProjectProfiler(make_settings()).profile(target)

    assert profile.project_type == "library"
    assert "library_requires_harness_or_host_application" in profile.non_runnable_reasons
    assert "library_harness" in profile.weak_verification_strategies


def test_recon_agent_includes_tool_availability(tmp_path: Path):
    target = tmp_path / "project"
    target.mkdir()
    (target / "app.py").write_text("print('ok')\n", encoding="utf-8")

    profile, event = ReconAgent(make_settings()).run(target)

    assert event.status == "completed"
    assert profile.tool_availability
    assert any(item["name"] == "semgrep" for item in profile.tool_availability)
    assert "available_tools" in profile.profile_summary


def test_recon_agent_adds_dependency_summary_and_hints(tmp_path: Path):
    target = tmp_path / "project"
    target.mkdir()
    (target / "requirements.txt").write_text("flask\n", encoding="utf-8")
    (target / "app.py").write_text("import os\nos.system('id')\n", encoding="utf-8")

    runner = ToolRunner(make_settings())
    runner.env["PATH"] = ""
    planner = ToolPlanner(runner.registry, runner.env)
    profile, _ = ReconAgent(make_settings(), tool_runner=runner, tool_planner=planner).run(target)

    assert profile.recommended_tool_details
    assert any(item["name"] == "osv-scanner" for item in profile.recommended_tool_details)
    assert profile.dependency_findings_summary
    assert profile.attack_priorities
    assert profile.verification_hints
    assert "narrative" in profile.profile_summary
    assert profile.recon_evidence_refs


def test_target_resolver_prefers_existing_local_path():
    resolver = TargetResolver(Path("runs"))
    source = resolver.resolve("examples/vulnerable-python")

    assert source.kind == "local"
    assert source.local_path.endswith("examples\\vulnerable-python") or source.local_path.endswith(
        "examples/vulnerable-python"
    )


def test_target_resolver_skips_pull_when_cached_repo_has_tracked_changes(tmp_path: Path):
    remote = tmp_path / "remote.git"
    seed = tmp_path / "seed"
    workspace = tmp_path / "runs"
    url = "https://github.com/example/dirty.git"
    repo_id = __import__("hashlib").sha1(url.encode("utf-8")).hexdigest()[:12]
    cached = workspace / "repos" / repo_id

    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True, text=True)
    subprocess.run(["git", "clone", str(remote), str(seed)], check=True, capture_output=True, text=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=seed, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=seed, check=True)
    (seed / "src").mkdir()
    (seed / "src" / "basicio.cpp").write_text("int old_value = 1;\n", encoding="utf-8")
    subprocess.run(["git", "add", "src/basicio.cpp"], cwd=seed, check=True)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=seed, check=True, capture_output=True, text=True)
    subprocess.run(["git", "push", "origin", "HEAD:main"], cwd=seed, check=True, capture_output=True, text=True)
    subprocess.run(["git", "clone", str(remote), str(cached)], check=True, capture_output=True, text=True)
    subprocess.run(["git", "checkout", "main"], cwd=cached, check=True, capture_output=True, text=True)

    (cached / "src" / "basicio.cpp").write_text("int local_change = 2;\n", encoding="utf-8")
    source = TargetResolver(workspace).resolve("example/dirty")

    assert source.kind == "git"
    assert Path(source.local_path) == cached.resolve()
    assert (cached / "src" / "basicio.cpp").read_text(encoding="utf-8") == "int local_change = 2;\n"


def test_target_resolver_normalizes_github_tree_url_to_branch_clone(tmp_path: Path, monkeypatch):
    import shutil

    workspace = tmp_path / "runs"
    commands: list[list[str]] = []
    monkeypatch.setattr(shutil, "which", lambda name: "git" if name == "git" else None)

    def fake_run_git(self, command: list[str], cwd: Path) -> str:
        commands.append(command)
        if command[:3] == ["git", "ls-remote", "--heads"]:
            return "abc\trefs/tags/v2.7.5\n"
        if command[:3] == ["git", "clone", "--depth"]:
            repo_dir = Path(command[-1])
            (repo_dir / ".git").mkdir(parents=True)
            return ""
        if command == ["git", "rev-parse", "HEAD"]:
            return "abc123\n"
        raise AssertionError(command)

    monkeypatch.setattr(TargetResolver, "_run_git", fake_run_git)

    source = TargetResolver(workspace).resolve("https://github.com/OpenVPN/openvpn/tree/v2.7.5.git")

    assert source.commit == "abc123"
    assert [
        "git",
        "clone",
        "--depth",
        "1",
        "--branch",
        "v2.7.5",
        "--single-branch",
        "https://github.com/OpenVPN/openvpn.git",
        source.local_path,
    ] in commands


def test_target_resolver_resolves_slash_branch_before_tree_path(tmp_path: Path, monkeypatch):
    import shutil

    workspace = tmp_path / "runs"
    commands: list[list[str]] = []
    monkeypatch.setattr(shutil, "which", lambda name: "git" if name == "git" else None)

    def fake_run_git(self, command: list[str], cwd: Path) -> str:
        commands.append(command)
        if command[:3] == ["git", "ls-remote", "--heads"]:
            return "\n".join(
                [
                    "abc\trefs/heads/main",
                    "def\trefs/heads/release/v2.7.5",
                ]
            )
        if command[:3] == ["git", "clone", "--depth"]:
            repo_dir = Path(command[-1])
            (repo_dir / ".git").mkdir(parents=True)
            return ""
        if command == ["git", "rev-parse", "HEAD"]:
            return "def456\n"
        raise AssertionError(command)

    monkeypatch.setattr(TargetResolver, "_run_git", fake_run_git)

    source = TargetResolver(workspace).resolve("https://github.com/OpenVPN/openvpn/tree/release/v2.7.5/src/openvpn")

    assert source.commit == "def456"
    assert [
        "git",
        "clone",
        "--depth",
        "1",
        "--branch",
        "release/v2.7.5",
        "--single-branch",
        "https://github.com/OpenVPN/openvpn.git",
        source.local_path,
    ] in commands


def test_dangerous_locator_and_slice_include_source_sink(tmp_path: Path):
    target = tmp_path / "project"
    target.mkdir()
    (target / "app.py").write_text(
        "import os\n\ndef ping(host):\n    value = input('host')\n    return os.system(value)\n",
        encoding="utf-8",
    )

    dangerous = DangerousFunctionLocator().locate(target, [])
    slices = SliceAnalyzer().analyze(target, dangerous, SemanticIndex(), FakeLLM())  # type: ignore[arg-type]

    assert dangerous
    assert dangerous[0].category == "command"
    assert slices
    assert slices[0].sink in {"os.system", "system"}
    assert slices[0].function_name == "ping"
    assert slices[0].sink_args
    assert slices[0].code_excerpt


def test_rules_loader_and_locator_load_language_rules(tmp_path: Path):
    target = tmp_path / "project"
    target.mkdir()
    (target / "app.py").write_text("import os\n\ndef run(cmd):\n    os.system(cmd)\n", encoding="utf-8")

    rules = RulesLoader().load()
    dangerous = DangerousFunctionLocator().locate(target, [])

    assert rules["python.dangerous_apis"]["rules"]
    assert dangerous
    assert dangerous[0].rule_id.startswith("rules.")


def test_slice_analyzer_javascript_fallback_path(tmp_path: Path):
    target = tmp_path / "project"
    target.mkdir()
    (target / "app.js").write_text("function run(cmd) {\n  return child_process.exec(cmd)\n}\n", encoding="utf-8")

    dangerous = DangerousFunctionLocator().locate(target, [])
    slices = SliceAnalyzer().analyze(target, dangerous, SemanticIndex(), FakeLLM())  # type: ignore[arg-type]

    assert slices
    assert slices[0].function_name == "run"


def test_slice_analyzer_cpp_regex_fallback_when_ctags_missing(tmp_path: Path, monkeypatch):
    target = tmp_path / "native"
    target.mkdir()
    (target / "main.cpp").write_text(
        "int run(char *dst, const char *src) {\n    return strcpy(dst, src) != 0;\n}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("agentic_code_audit.agents.mining.shutil.which", lambda _name: None)

    dangerous = DangerousFunctionLocator().locate(target, [])
    slices = SliceAnalyzer().analyze(target, dangerous, SemanticIndex(), FakeLLM())  # type: ignore[arg-type]

    assert dangerous
    assert dangerous[0].function_name == "run"
    assert slices
    assert slices[0].function_name == "run"


def test_candidate_without_function_is_invalid():
    program_slice = ProgramSlice(
        id="slice-1",
        dangerous_function_id="danger-1",
        file_path="app.py",
        line_start=12,
        function_name="",
        source="request.args",
        sink="os.system",
        context="12: os.system(value)",
    )

    candidates = CandidateGenerator().generate([program_slice], FakeLLM())  # type: ignore[arg-type]

    assert candidates
    assert candidates[0].valid is False
    assert candidates[0].validity == "invalid_candidate"


def test_candidate_generator_accepts_labeled_confidence():
    class ConfidenceLLM:
        enabled = True

        def chat(self, *_args, **_kwargs):
            return type(
                "Resp",
                (),
                {
                    "ok": True,
                    "content": (
                        '[{"title":"command injection","vulnerability_type":"command_injection",'
                        '"severity":"high","description":"input reaches shell",'
                        '"trigger_condition":"request args reaches os.system",'
                        '"evidence":["source to sink"],"confidence":"high","valid":true}]'
                    ),
                    "error": "",
                },
            )()

    program_slice = ProgramSlice(
        id="slice-1",
        dangerous_function_id="danger-1",
        file_path="app.py",
        line_start=12,
        function_name="ping",
        source="request.args",
        sink="os.system",
        context="12: os.system(value)",
    )

    candidates = CandidateGenerator().generate([program_slice], ConfidenceLLM())  # type: ignore[arg-type]

    assert candidates
    assert candidates[0].confidence == 0.8
    assert candidates[0].severity == "high"


def test_coerce_str_list_preserves_string_as_single_item():
    assert coerce_str_list("GitHub Actions") == ["GitHub Actions"]
    assert coerce_str_list(["source", "sink"]) == ["source", "sink"]
    assert coerce_str_list(None) == []


def test_llm_string_evidence_is_not_split_into_characters():
    class EvidenceLLM:
        enabled = True

        def chat(self, *_args, **_kwargs):
            return type(
                "Resp",
                (),
                {
                    "ok": True,
                    "content": (
                        '[{"title":"command injection","vulnerability_type":"command_injection",'
                        '"severity":"high","description":"input reaches shell",'
                        '"trigger_condition":"request args reaches os.system",'
                        '"evidence":"GitHub Actions","confidence":"high","valid":true}]'
                    ),
                    "error": "",
                },
            )()

    program_slice = ProgramSlice(
        id="slice-1",
        dangerous_function_id="danger-1",
        file_path="app.py",
        line_start=12,
        function_name="ping",
        source="request.args",
        sink="os.system",
        context="12: os.system(value)",
    )

    candidates = CandidateGenerator().generate([program_slice], EvidenceLLM())  # type: ignore[arg-type]

    assert candidates[0].evidence == ["GitHub Actions"]


def test_audit_budget_modes_are_enforced_in_mining_components(tmp_path: Path):
    target = tmp_path / "project"
    target.mkdir()
    for idx in range(20):
        (target / f"app{idx}.py").write_text(
            f"import os\n\ndef run{idx}(cmd):\n    return os.system(cmd)\n",
            encoding="utf-8",
        )
    budget = AuditBudget.for_mode("quick")

    dangerous = DangerousFunctionLocator().locate(target, [], budget)
    slices = SliceAnalyzer().analyze(target, dangerous, SemanticIndex(), FakeLLM(), budget)  # type: ignore[arg-type]
    candidates = CandidateGenerator().generate(slices, FakeLLM(), budget)  # type: ignore[arg-type]

    assert len(dangerous) <= budget.max_anchors
    assert len(slices) <= budget.max_slices
    assert len(candidates) <= budget.max_candidates


def test_quick_budget_suppresses_config_anchors(tmp_path: Path):
    target = tmp_path / "repo"
    workflow = target / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("steps:\n  - uses: actions/checkout@master\n", encoding="utf-8")
    semgrep_result = ToolResult(
        tool="semgrep",
        status="ok",
        run_id="semgrep-run",
        raw={
            "results": [
                {
                    "path": ".github/workflows/ci.yml",
                    "start": {"line": 2},
                    "check_id": "yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag",
                    "extra": {"lines": "uses: actions/checkout@master", "message": "Action tag is mutable."},
                }
            ]
        },
    )

    dangerous = DangerousFunctionLocator().locate(target, [semgrep_result], AuditBudget.for_mode("quick"))

    assert dangerous == []


def test_mining_director_rejects_invalid_strategy_items(tmp_path: Path):
    target = tmp_path / "repo"
    (target / "src").mkdir(parents=True)
    (target / ".github" / "workflows").mkdir(parents=True)
    (target / "src" / "parser.cpp").write_text("void parseImage() {}\n", encoding="utf-8")
    (target / ".github" / "workflows" / "ci.yml").write_text("uses: actions/checkout@master\n", encoding="utf-8")
    profile = ProjectProfile(root=str(target), languages={"C++": 1})
    semantic_index = SemanticIndex(
        functions=[FunctionSummary(name="parseImage", file_path="src/parser.cpp", line_start=1, signature="", summary="")]
    )
    tools = [
        ToolAvailability("semgrep", "semgrep", True, False, "static-analysis"),
        ToolAvailability("cppcheck", "cppcheck", False, False, "cpp-static-analysis", reason="missing"),
    ]
    strategy = MiningStrategy(
        tool_selections=[
            ToolSelection(name="cppcheck", priority=1),
            ToolSelection(name="semgrep", priority=2),
            ToolSelection(name="unknown-tool", priority=1),
        ],
        focus_directories=["src", "missing"],
        priority_functions=["parseImage", "missingFunc"],
        parser_entries=["decode", "notRealParser"],
        dynamic_priority_functions=["parseImage", "notRealDynamic"],
        confirmed_high_risk=[
            {"file": ".github/workflows/ci.yml", "function": "", "reason": "do not promote config"},
            {"file": "src/parser.cpp", "function": "missingFunc", "reason": "unknown function"},
        ],
        dismissed_noise=[{"file": ".github/workflows/ci.yml", "reason": "config lint"}],
        confidence="high",  # type: ignore[arg-type]
    )

    validated = MiningDirector(FakeLLM()).validate_strategy(strategy, target, tools, profile, semantic_index)  # type: ignore[arg-type]

    assert [item.name for item in validated.tool_selections] == ["semgrep"]
    assert validated.focus_directories == ["src"]
    assert validated.priority_functions == ["parseImage"]
    assert "decode" in validated.parser_entries
    assert "parseImage" in validated.dynamic_priority_functions
    assert validated.dismissed_noise == [{"file": ".github/workflows/ci.yml", "reason": "config lint"}]
    assert validated.confirmed_high_risk == []
    rejected = {(item["kind"], item["value"]) for item in validated.rejected_strategy_items}
    assert ("tool", "cppcheck") in rejected
    assert ("tool", "unknown-tool") in rejected
    assert ("focus_directory", "missing") in rejected
    assert ("priority_function", "missingFunc") in rejected
    assert ("confirmed_high_risk", ".github/workflows/ci.yml") in rejected
    assert validated.confidence == 0.8


def test_mining_director_fallback_strategy_is_not_empty(tmp_path: Path):
    class BrokenLLM:
        def chat(self, *_args, **_kwargs):
            raise RuntimeError("llm down")

    target = tmp_path / "repo"
    (target / "src").mkdir(parents=True)
    profile = ProjectProfile(root=str(target), languages={"Python": 1})
    tools = [ToolAvailability("semgrep", "semgrep", True, False, "static-analysis")]

    strategy = MiningDirector(BrokenLLM()).formulate_strategy(target, profile, SemanticIndex(), tools)  # type: ignore[arg-type]

    assert strategy.validated is True
    assert strategy.tool_selections
    assert strategy.focus_directories == ["src"]


def test_mining_director_prioritizes_candidates_and_adds_hints():
    director = MiningDirector(FakeLLM())  # type: ignore[arg-type]
    strategy = MiningStrategy(
        focus_directories=["src"],
        priority_functions=["parseImage"],
        parser_entries=["parse"],
        dynamic_priority_functions=["parseImage"],
        verification_hints={"parseImage": {"runtime_type": "cpp_harness", "oracle": "asan crash"}},
    )
    boring = VulnerabilityCandidate(
        id="candidate-b",
        slice_id="slice-b",
        title="boring",
        vulnerability_type="other",
        severity="low",
        file_path="docs/readme.md",
        line_start=1,
        description="boring",
        function_name="readme",
        confidence=0.9,
    )
    parser = VulnerabilityCandidate(
        id="candidate-a",
        slice_id="slice-a",
        title="parser overflow",
        vulnerability_type="buffer_overflow",
        severity="high",
        file_path="src/parser.cpp",
        line_start=10,
        description="parser",
        function_name="parseImage",
        confidence=0.5,
    )

    ordered = director.prioritize_candidates([boring, parser], strategy, ProjectProfile(root="", languages={"C++": 1}))

    assert ordered[0].id == "candidate-a"
    assert ordered[0].director_priority > ordered[1].director_priority
    assert "priority_function:parseImage" in ordered[0].director_reason
    assert ordered[0].verification_hint["runtime_type"] == "cpp_harness"


def test_mining_debug_and_report_include_director_strategy(tmp_path: Path):
    strategy = MiningStrategy(
        tool_selections=[ToolSelection(name="semgrep", priority=1)],
        focus_directories=["src"],
        priority_functions=["parseImage"],
        rejected_strategy_items=[{"kind": "tool", "value": "cppcheck", "reason": "tool is unavailable"}],
        strategy_effects={"candidate_top_after": ["candidate-1"]},
    )
    mining_result = MiningResult(
        dangerous_functions=[
            DangerousFunction(
                id="df-source",
                file_path="src/parser.cpp",
                line_start=1,
                function_name="parseImage",
                dangerous_api="memcpy",
                category="memory",
                snippet="memcpy(dst, src, len)",
                risk_domain="source_code",
            ),
            DangerousFunction(
                id="df-config",
                file_path=".github/workflows/build.yml",
                line_start=3,
                function_name="",
                dangerous_api="mutable_action_ref",
                category="configuration",
                snippet="uses: vendor/action@main",
                risk_domain="supply_chain_config",
            ),
        ],
        candidates=[
            VulnerabilityCandidate(
                id="candidate-1",
                slice_id="slice-1",
                title="candidate",
                vulnerability_type="buffer_overflow",
                severity="high",
                file_path="src/parser.cpp",
                line_start=1,
                description="candidate",
            )
        ],
        aggregated_candidates=[],
        findings=[],
        strategy=strategy.to_dict(),
        strategy_effects=strategy.strategy_effects,
    )

    debug = generate_mining_debug(mining_result)

    assert debug["validated_strategy"]["focus_directories"] == ["src"]
    assert debug["rejected_strategy_items"][0]["value"] == "cppcheck"
    assert debug["strategy_effects"]["candidate_top_after"] == ["candidate-1"]
    assert debug["anchor_count_by_risk_domain"] == {"source_code": 1, "supply_chain_config": 1}

    report = AuditReport(
        input_source=InputSource(original="local", kind="local", local_path=str(tmp_path)),
        target=str(tmp_path),
        created_at="now",
        profile=ProjectProfile(root=str(tmp_path), languages={"C++": 1}),
        semantic_index=SemanticIndex(),
        tool_results=[],
        dangerous_functions=[],
        program_slices=[],
        candidates=[],
        findings=[],
        verification_results=[],
        mining_strategy=strategy.to_dict(),
    )

    markdown = ReportWriter()._to_markdown(report)

    assert "## MiningDirector 策略" in markdown
    assert "被拒绝的策略项" in markdown
    assert "candidate-1" in markdown


def test_weak_cpp_rule_without_strong_condition_is_invalid(tmp_path: Path):
    target = tmp_path / "native"
    target.mkdir()
    (target / "main.cpp").write_text(
        "int f(const char *a, const char *b) {\n    return memcmp(a, b, 4);\n}\n",
        encoding="utf-8",
    )

    dangerous = DangerousFunctionLocator().locate(target, [], AuditBudget.for_mode("standard"))
    slices = SliceAnalyzer().analyze(target, dangerous, SemanticIndex(), FakeLLM(), AuditBudget.for_mode("standard"))  # type: ignore[arg-type]
    candidates = CandidateGenerator().generate(slices, FakeLLM(), AuditBudget.for_mode("standard"))  # type: ignore[arg-type]

    assert candidates
    assert all(candidate.validity == "invalid_candidate" for candidate in candidates)
    assert ClueAggregator().aggregate(candidates) == []


def test_invalid_candidate_is_not_aggregated():
    candidate = VulnerabilityCandidate(
        id="candidate-1",
        slice_id="slice-1",
        title="invalid",
        vulnerability_type="command_injection",
        severity="high",
        file_path="app.py",
        line_start=12,
        description="invalid",
        valid=False,
        validity="invalid_candidate",
    )

    assert ClueAggregator().aggregate([candidate]) == []


def test_config_security_candidate_without_function_is_reportable(tmp_path: Path):
    target = tmp_path / "repo"
    workflow = target / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "name: ci\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - uses: actions/checkout@master\n",
        encoding="utf-8",
    )
    semgrep_result = ToolResult(
        tool="semgrep",
        status="ok",
        run_id="semgrep-run",
        raw={
            "results": [
                {
                    "path": ".github/workflows/ci.yml",
                    "start": {"line": 5},
                    "check_id": "yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag",
                    "extra": {"lines": "uses: actions/checkout@master", "message": "Action tag is mutable."},
                }
            ]
        },
        parsed_artifact_id="artifact-semgrep",
    )

    dangerous = DangerousFunctionLocator().locate(target, [semgrep_result])
    slices = SliceAnalyzer().analyze(target, dangerous, SemanticIndex(), FakeLLM())  # type: ignore[arg-type]
    candidates = CandidateGenerator().generate(slices, FakeLLM())  # type: ignore[arg-type]
    aggregated = ClueAggregator().aggregate(candidates)
    findings = VulnerabilityClassifier().classify(aggregated, slices, FakeLLM())  # type: ignore[arg-type]

    assert dangerous[0].kind == "configuration_security"
    assert slices[0].source == "configuration file"
    assert candidates[0].validity == "valid"
    assert aggregated
    assert findings
    assert findings[0].vulnerability_type == "supply_chain_config"
    assert findings[0].should_verify is False


def test_classifier_adds_non_empty_effect_to_chain_graph():
    program_slice = ProgramSlice(
        id="slice-1",
        dangerous_function_id="danger-1",
        file_path="app.py",
        line_start=12,
        function_name="ping",
        source="request.args",
        sink="os.system",
        call_chain=["GET /ping", "ping", "os.system"],
        tool_run_refs=["run-1", "run-2"],
        artifact_refs=["artifact-1"],
        missing_guards=["input validation", "sanitization or allowlist"],
        context="12: os.system(value)",
    )
    candidate = VulnerabilityCandidate(
        id="candidate-1",
        slice_id="slice-1",
        title="命令注入候选",
        vulnerability_type="command_injection",
        severity="high",
        file_path="app.py",
        line_start=12,
        description="用户输入进入 os.system。",
        trigger_conditions=["host 参数可控"],
        evidence=["source=request.args", "sink=os.system"],
        confidence=0.7,
    )

    findings = VulnerabilityClassifier().classify([candidate], [program_slice], FakeLLM())  # type: ignore[arg-type]

    assert findings
    effect_nodes = [node for node in findings[0].chain_graph.nodes if node.type == "effect"]
    assert effect_nodes
    assert effect_nodes[0].label
    assert effect_nodes[0].detail
    assert len(findings[0].chain_graph.nodes) > 5
    node_labels = [node.label for node in findings[0].chain_graph.nodes]
    assert "GET /ping" in node_labels
    assert "input validation" in node_labels
    assert any(edge.type == "missing_control" for edge in findings[0].chain_graph.edges)
    assert findings[0].severity == "critical"
    assert findings[0].should_verify is True
    assert findings[0].tool_run_refs == ["run-1", "run-2"]
    assert findings[0].artifact_refs == ["artifact-1"]


def test_classifier_queues_source_code_findings_for_static_dynamic_gate():
    program_slice = ProgramSlice(
        id="slice-low-score",
        dangerous_function_id="danger-low-score",
        file_path="app.py",
        line_start=7,
        function_name="read_file",
        source="source literal",
        sink="open",
        context="7: open(path)",
    )
    candidate = VulnerabilityCandidate(
        id="candidate-low-score",
        slice_id="slice-low-score",
        title="Path traversal candidate",
        vulnerability_type="path_traversal",
        severity="medium",
        file_path="app.py",
        line_start=7,
        description="A file path reaches open().",
        evidence=["sink=open"],
        confidence=0.4,
    )

    findings = VulnerabilityClassifier().classify([candidate], [program_slice], FakeLLM())  # type: ignore[arg-type]

    assert findings
    assert findings[0].evidence_strength == "weak"
    assert findings[0].should_verify is True
    assert findings[0].needs_verification is True
    assert "Source-code finding is queued for static verification" in findings[0].verification_reason


def test_anypoc_cpp_verification_generates_artifacts(tmp_path: Path):
    target = tmp_path / "native"
    target.mkdir()
    (target / "main.cpp").write_text(
        "void f(char *dst, char *src) { strcpy(dst, src); }\n",
        encoding="utf-8",
    )
    finding = Finding(
        id="native-001",
        vulnerability_type="unsafe_c_string_api",
        severity="high",
        title="Unsafe strcpy",
        description="strcpy may overflow the destination buffer.",
        file_path="main.cpp",
        line_start=1,
        code_snippet="strcpy(dst, src)",
        evidence=["builtin native rule"],
        tool="builtin-patterns",
    )
    profile = ProjectProfile(root=str(target), languages={"C++": 1})

    results = VerificationAgent().verify(target, [finding], tmp_path / "out", profile)

    assert len(results) == 1
    result = results[0]
    assert result.method == "anypoc::cpp_cli"
    assert result.status == "blocked"
    assert Path(result.poc_path).exists()
    assert any(Path(path).name == "bug_report.md" for path in result.generated_artifacts)


def test_evidence_checker_does_not_verify_without_real_output(tmp_path: Path):
    target = tmp_path / "project"
    target.mkdir()
    (target / "app.py").write_text("def f(x):\n    return x\n", encoding="utf-8")
    finding = Finding(
        id="f-1",
        vulnerability_type="command_injection",
        severity="high",
        title="test",
        description="test",
        file_path="app.py",
        line_start=1,
    )
    plan = PocPlan(
        finding=finding,
        analysis=PocAnalysis("valid", "manual_review", "marker required", "test"),
        poc_dir=tmp_path / "poc",
        poc_path=tmp_path / "poc" / "poc.md",
    )
    outcome = EvidenceChecker().check(target, plan)
    assert outcome.status == "uncertain"


def test_save_report_registers_artifacts_and_finding_trace(tmp_path: Path):
    store = AuditStore(tmp_path / "audit.sqlite3")
    task_id = store.create_task("examples/vulnerable-python", "full", "deepseek-v4-pro", "", False)

    tool_out = tmp_path / "tool.out"
    tool_err = tmp_path / "tool.err"
    tool_parsed = tmp_path / "tool.json"
    for path, content in [(tool_out, "stdout"), (tool_err, "stderr"), (tool_parsed, "{\"ok\": true}")]:
        path.write_text(content, encoding="utf-8")

    verification_file = tmp_path / "bug_report.md"
    verification_file.write_text("# bug\n", encoding="utf-8")
    report_dir = tmp_path / "report"
    report_dir.mkdir()
    json_report = report_dir / "audit-report.json"
    markdown_report = report_dir / "audit-report.md"
    json_report.write_text("{}", encoding="utf-8")
    markdown_report.write_text("# report\n", encoding="utf-8")

    tool_records = [
        ArtifactRecord(id="stdout-1", kind="tool_stdout", path=str(tool_out)),
        ArtifactRecord(id="stderr-1", kind="tool_stderr", path=str(tool_err)),
        ArtifactRecord(id="parsed-1", kind="tool_parsed", path=str(tool_parsed)),
    ]
    verification_records = [ArtifactRecord(id="verify-1", kind="verification_output", path=str(verification_file))]
    tool_result = ToolResult(
        tool="semgrep",
        status="ok",
        run_id="run-1",
        command=["semgrep"],
        summary="ok",
        stdout_artifact_id="stdout-1",
        stderr_artifact_id="stderr-1",
        parsed_artifact_id="parsed-1",
        artifact_records=tool_records,
    )
    dangerous = DangerousFunction(
        id="danger-1",
        file_path="app.py",
        line_start=10,
        function_name="ping",
        dangerous_api="os.system",
        category="command",
        snippet="os.system(value)",
        tool_run_refs=["run-1"],
        artifact_refs=["parsed-1"],
    )
    program_slice = ProgramSlice(
        id="slice-1",
        dangerous_function_id="danger-1",
        file_path="app.py",
        line_start=10,
        function_name="ping",
        source="request.args",
        sink="os.system",
        tool_run_refs=["run-1"],
        artifact_refs=["parsed-1"],
        context="10: os.system(value)",
        code_excerpt="os.system(value)",
    )
    candidate = VulnerabilityCandidate(
        id="candidate-1",
        slice_id="slice-1",
        title="command injection",
        vulnerability_type="command_injection",
        severity="high",
        file_path="app.py",
        line_start=10,
        description="input reaches os.system",
        function_name="ping",
        trigger_conditions=["request.args"],
        evidence_refs=["slice-1", "run-1", "parsed-1"],
    )
    finding = Finding(
        id="finding-1",
        vulnerability_type="command_injection",
        severity="high",
        title="command injection",
        description="input reaches os.system",
        file_path="app.py",
        line_start=10,
        source="request.args",
        sink="os.system",
        slice_id="slice-1",
        candidate_id="candidate-1",
        dangerous_function_id="danger-1",
        tool_run_refs=["run-1"],
        artifact_refs=["parsed-1"],
    )
    verification = VerificationResult(
        finding_id="finding-1",
        status="blocked",
        method="anypoc::manual_review",
        generated_artifacts=[str(verification_file)],
        artifact_ids=["verify-1"],
        artifact_records=verification_records,
    )
    report = AuditReport(
        input_source=InputSource(original="examples/vulnerable-python", kind="local", local_path="examples/vulnerable-python"),
        target="examples/vulnerable-python",
        created_at="2026-01-01T00:00:00+00:00",
        profile=ProjectProfile(root="examples/vulnerable-python"),
        semantic_index=SemanticIndex(),
        tool_results=[tool_result],
        dangerous_functions=[dangerous],
        program_slices=[program_slice],
        candidates=[candidate],
        findings=[finding],
        verification_results=[verification],
    )

    store.save_report(task_id, report, json_report, markdown_report)
    detail = store.get_finding(task_id, "finding-1")

    assert detail is not None
    assert detail["trace"]["candidate_id"] == "candidate-1"
    assert detail["trace"]["slice_id"] == "slice-1"
    assert detail["trace"]["dangerous_function_id"] == "danger-1"
    assert detail["trace"]["tool_runs"][0]["run_id"] == "run-1"
    assert {item["id"] for item in detail["trace"]["artifacts"]} >= {"parsed-1"}
    assert store.get_artifact("verify-1") is not None


def test_store_syncs_copied_report_directory_into_task_history(tmp_path: Path):
    store = AuditStore(tmp_path / "audit.sqlite3")
    reports_dir = tmp_path / "reports"
    report_dir = reports_dir / "imported-task"
    report_dir.mkdir(parents=True)
    (report_dir / "audit-report.md").write_text("# imported\n", encoding="utf-8")
    (report_dir / "audit-report.json").write_text(
        json.dumps(
            {
                "input_source": {
                    "original": "https://github.com/example/project",
                    "kind": "git",
                    "local_path": "/app/runs/repos/imported",
                    "commit": "abc123",
                },
                "target": "/app/runs/repos/imported",
                "created_at": "2026-07-14T00:00:00+00:00",
                "mode": "deep",
                "llm_provider": "openai-compatible",
                "llm_model": "test-model",
                "profile": {"root": "/app/runs/repos/imported", "project_type": "cli"},
                "tool_results": [],
                "dangerous_functions": [],
                "program_slices": [],
                "candidates": [],
                "findings": [
                    {
                        "id": "finding-1",
                        "title": "imported finding",
                        "severity": "high",
                        "vulnerability_type": "command_injection",
                        "file_path": "app.py",
                        "line_start": 12,
                    }
                ],
                "verification_results": [
                    {
                        "finding_id": "finding-1",
                        "status": "partial_dynamic_proof",
                        "method": "imported",
                        "proof_level": "micro_proof",
                    }
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    assert store.sync_report_directories(reports_dir) == 1
    assert store.sync_report_directories(reports_dir) == 0

    tasks = store.list_tasks()
    assert tasks[0]["id"] == "imported-task"
    assert tasks[0]["target"] == "https://github.com/example/project"
    assert tasks[0]["status"] == "completed"
    assert tasks[0]["report_dir"] == str(report_dir)
    assert tasks[0]["json_report"] == str(report_dir / "audit-report.json")
    assert tasks[0]["commit"] == "abc123"

    findings = store.list_findings("imported-task")
    assert len(findings) == 1
    assert findings[0]["title"] == "imported finding"
    assert findings[0]["verification"]["status"] == "partial_dynamic_proof"
    assert store.get_project_profile("imported-task")["project_type"] == "cli"


def test_report_writer_outputs_chinese_trace_and_verification_sections(tmp_path: Path):
    report = AuditReport(
        input_source=InputSource(original="examples/vulnerable-python", kind="local", local_path="examples/vulnerable-python"),
        target="examples/vulnerable-python",
        created_at="2026-01-01T00:00:00+00:00",
        profile=ProjectProfile(
            root="examples/vulnerable-python",
            languages={"Python": 1},
            recommended_tools=["semgrep"],
            attack_priorities=["command injection"],
            verification_hints=["run python harness"],
            build_entries=[{"kind": "python", "file": "pyproject.toml", "command": "pip install ."}],
            runtime_entries=[{"kind": "python", "file": "app.py", "command": "python app.py"}],
            test_entries=[{"kind": "pytest", "file": "tests", "command": "pytest"}],
            verification_entries=[{"kind": "harness", "file": "harness.py", "command": "python harness.py"}],
        ),
        semantic_index=SemanticIndex(),
        tool_results=[],
        dangerous_functions=[],
        program_slices=[],
        candidates=[],
        findings=[
            Finding(
                id="finding-1",
                vulnerability_type="command_injection",
                severity="high",
                title="命令注入",
                description="用户输入到达 os.system",
                file_path="app.py",
                line_start=10,
                candidate_id="candidate-1",
                slice_id="slice-1",
                dangerous_function_id="danger-1",
                tool_run_refs=["run-1"],
                artifact_refs=["artifact-1"],
                recommendation="使用参数数组并增加 allowlist。",
            )
        ],
        verification_results=[
            VerificationResult(
                finding_id="finding-1",
                status="blocked",
                method="anypoc::manual_harness",
                runtime_type="python_test",
                strategy="python_harness_or_pytest",
                environment_gaps=["missing tool: docker"],
                payloads=["name=$(id)"],
                execution={"command": ["python", "harness.py"], "exit_code": 0},
                checker_details={"checker": "CommandInjectionChecker"},
                evidence_artifact_ids=["evidence-1"],
                exploit_artifact_ids=["exploit-1"],
                artifact_records=[
                    ArtifactRecord(
                        id="evidence-1",
                        kind="verification_output",
                        path=str(tmp_path / "verification.json"),
                    )
                ],
            )
        ],
    )

    json_path, markdown_path = ReportWriter().write(report, tmp_path)
    markdown = markdown_path.read_text(encoding="utf-8")

    assert json_path.exists()
    assert "# Agentic Code Audit 安全审计报告" in markdown
    assert "## 报告信息" in markdown
    assert "## 执行摘要" in markdown
    assert "### 漏洞发现概览" in markdown
    assert "## 高危 (High) 漏洞" in markdown
    assert "### HIGH-1: 命令注入" in markdown
    assert "**漏洞描述:**" in markdown
    assert "**证据链:**" in markdown
    assert "## 验证证据" in markdown
    assert "## Artifact 索引" in markdown
    assert "**复现步骤:**" in markdown
    assert "**PoC 代码:**" in markdown
    assert "python harness.py" in markdown
    assert "## 构建入口" not in markdown
    assert "## 运行入口" not in markdown
    assert "## 测试入口" not in markdown
    assert "## 验证入口" not in markdown
    assert "runtime_type" not in markdown.lower() or "运行类型" in markdown
    assert "evidence_artifact_ids: `evidence-1`" in markdown
    assert "鏅鸿兘" not in markdown


def test_report_writer_renders_poc_as_chinese_steps_and_code_not_raw_all_a(tmp_path: Path):
    run_script = tmp_path / "run_poc.sh"
    run_script.write_text(
        "set -e\n"
        "${CC:-cc} -fsanitize=address,undefined poc_harness.c -o poc_harness\n"
        "./poc_harness < poc_input.txt\n",
        encoding="utf-8",
    )
    finding = Finding(
        id="finding-native",
        vulnerability_type="unsafe_c_string_api",
        severity="high",
        title="不安全 C 字符串拷贝",
        description="stdin reaches strcpy",
        file_path="src/openvpn/misc.c",
        line_start=42,
        function_name="management_query_user_pass_enabled",
        source="stdin",
        sink="strcpy",
        cwe="CWE-120",
        recommendation="Replace unsafe C string APIs with bounded variants.",
        exploit_payloads=["A" * 64],
    )
    verification = VerificationResult(
        finding_id=finding.id,
        status="partial_dynamic_proof",
        method="anypoc::cpp_cli",
        reproduction="Partial dynamic proof executed after full runtime was blocked.",
        proof_level="micro_proof",
        oracle="ASAN/UBSAN",
        payloads=["A" * 64],
        generated_artifacts=[str(run_script)],
    )
    report = AuditReport(
        input_source=InputSource(original="openvpn", kind="git", local_path="openvpn"),
        target="openvpn",
        created_at="2026-01-01T00:00:00+00:00",
        profile=ProjectProfile(root="openvpn", languages={"C": 1}),
        semantic_index=SemanticIndex(),
        tool_results=[],
        dangerous_functions=[],
        program_slices=[],
        candidates=[],
        findings=[finding],
        verification_results=[verification],
    )

    markdown = ReportWriter()._to_markdown(report)
    poc_section = markdown.split("**概念验证 (PoC):**", 1)[1].split("**证据链:**", 1)[0]

    assert "避免继续使用不带边界检查的 C 字符串/内存操作接口" in markdown
    assert "Replace unsafe C string APIs" not in markdown
    assert "完整项目构建或运行受阻后" in poc_section
    assert "**复现步骤:**" in poc_section
    assert "**PoC 代码:**" in poc_section
    assert "./poc_harness < poc_input.txt" in poc_section
    assert "Partial dynamic proof executed after full runtime was blocked." not in poc_section
    assert "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" not in poc_section


def test_report_writer_fallback_poc_is_command_template_not_raw_all_a():
    finding = Finding(
        id="finding-stdin",
        vulnerability_type="unsafe_c_string_api",
        severity="high",
        title="stdin 到 strcpy",
        description="stdin reaches strcpy",
        file_path="main.c",
        line_start=7,
        function_name="parse",
        source="stdin",
        sink="strcpy",
        recommendation="Replace unsafe C string APIs with bounded variants.",
        exploit_payloads=["A" * 128],
    )
    report = AuditReport(
        input_source=InputSource(original="local", kind="local", local_path="local"),
        target="local",
        created_at="2026-01-01T00:00:00+00:00",
        profile=ProjectProfile(root="local", languages={"C": 1}),
        semantic_index=SemanticIndex(),
        tool_results=[],
        dangerous_functions=[],
        program_slices=[],
        candidates=[],
        findings=[finding],
        verification_results=[],
    )

    markdown = ReportWriter()._to_markdown(report)
    poc_section = markdown.split("**概念验证 (PoC):**", 1)[1].split("**证据链:**", 1)[0]

    assert "cat > poc_input.txt <<'EOF'" in poc_section
    assert "agentic_audit_case=finding-stdin" in poc_section
    assert "payload=<根据目标协议填写触发字段>" in poc_section
    assert "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" not in poc_section


def test_report_writer_filters_manual_validation_payload_from_legacy_findings():
    finding = Finding(
        id="finding-manual-placeholder",
        vulnerability_type="other",
        severity="medium",
        title="legacy placeholder",
        description="legacy placeholder",
        file_path="app.php",
        line_start=1,
        source="request",
        sink="php.lang.security.exec-use.exec-use",
        exploit_payloads=["manual-validation-payload"],
    )
    report = AuditReport(
        input_source=InputSource(original="local", kind="local", local_path="local"),
        target="local",
        created_at="2026-01-01T00:00:00+00:00",
        profile=ProjectProfile(root="local", languages={"PHP": 1}),
        semantic_index=SemanticIndex(),
        tool_results=[],
        dangerous_functions=[],
        program_slices=[],
        candidates=[],
        findings=[finding],
        verification_results=[],
    )

    markdown = ReportWriter()._to_markdown(report)

    assert "manual-validation-payload" not in markdown
    assert "[含 PoC]" not in markdown
    assert "payload=<根据目标协议填写触发字段>" in markdown


def test_report_json_endpoint_returns_file_and_404(tmp_path: Path, monkeypatch):
    import agentic_code_audit.server as server_module

    store = AuditStore(tmp_path / "audit.sqlite3")
    task_id = store.create_task("examples/vulnerable-python", "full", "deepseek-v4-pro", "", False)
    report_dir = tmp_path / "report"
    report_dir.mkdir()
    json_report = report_dir / "audit-report.json"
    markdown_report = report_dir / "audit-report.md"
    json_report.write_text('{"ok": true}', encoding="utf-8")
    markdown_report.write_text("# report\n", encoding="utf-8")
    report = AuditReport(
        input_source=InputSource(original="examples/vulnerable-python", kind="local", local_path="examples/vulnerable-python"),
        target="examples/vulnerable-python",
        created_at="2026-01-01T00:00:00+00:00",
        profile=ProjectProfile(root="examples/vulnerable-python"),
        semantic_index=SemanticIndex(),
        tool_results=[],
        dangerous_functions=[],
        program_slices=[],
        candidates=[],
        findings=[],
        verification_results=[],
    )
    store.save_report(task_id, report, json_report, markdown_report)
    monkeypatch.setattr(server_module, "STORE", store)

    client = TestClient(server_module.app)
    ok = client.get(f"/api/tasks/{task_id}/report.json")
    missing = client.get("/api/tasks/missing/report.json")

    assert ok.status_code == 200
    assert ok.json()["ok"] is True
    assert missing.status_code == 404


def test_delete_task_endpoint_removes_task_and_rejects_running(tmp_path: Path, monkeypatch):
    import agentic_code_audit.server as server_module

    store = AuditStore(tmp_path / "audit.sqlite3")
    task_id = store.create_task("examples/vulnerable-python", "full", "deepseek-v4-pro", "", False)
    running_id = store.create_task("examples/vulnerable-python", "full", "deepseek-v4-pro", "", False)
    store.mark_running(running_id)
    monkeypatch.setattr(server_module, "STORE", store)

    client = TestClient(server_module.app)
    blocked = client.delete(f"/api/tasks/{running_id}")
    deleted = client.delete(f"/api/tasks/{task_id}")
    missing = client.get(f"/api/tasks/{task_id}")

    assert blocked.status_code == 409
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True
    assert missing.status_code == 404


def test_recon_to_mining_store_persistence_end_to_end(tmp_path: Path):
    from agentic_code_audit.agents.mining import VulnerabilityMiningAgent

    target = tmp_path / "project"
    target.mkdir()
    (target / "app.py").write_text(
        "import os\n\ndef ping():\n    value = input('host')\n    return os.system(value)\n",
        encoding="utf-8",
    )

    settings = make_settings()
    runner = ToolRunner(settings)
    runner.env["PATH"] = ""
    planner = ToolPlanner(runner.registry, runner.env)
    profile, _ = ReconAgent(settings, tool_runner=runner, tool_planner=planner).run(target)
    mining_agent = VulnerabilityMiningAgent(
        tool_runner=runner,
        llm_client=FakeLLM(),  # type: ignore[arg-type]
        tool_planner=planner,
    )
    mining = mining_agent.run(target, profile, SemanticIndex())
    store = AuditStore(tmp_path / "audit.sqlite3")
    task_id = store.create_task(str(target), "full", "deepseek-v4-pro", "", False)
    report_dir = tmp_path / "report"
    report_dir.mkdir()
    json_report = report_dir / "audit-report.json"
    markdown_report = report_dir / "audit-report.md"
    json_report.write_text("{}", encoding="utf-8")
    markdown_report.write_text("# report\n", encoding="utf-8")
    report = AuditReport(
        input_source=InputSource(original=str(target), kind="local", local_path=str(target)),
        target=str(target),
        created_at="2026-01-01T00:00:00+00:00",
        profile=profile,
        semantic_index=SemanticIndex(),
        tool_results=mining.tool_results,
        dangerous_functions=mining.dangerous_functions,
        program_slices=mining.program_slices,
        candidates=mining.candidates,
        findings=mining.findings,
        verification_results=[],
    )

    store.save_report(task_id, report, json_report, markdown_report)
    saved_profile = store.get_project_profile(task_id)
    saved_findings = store.list_findings(task_id)

    assert saved_profile is not None
    assert "recommended_tool_details" in saved_profile
    assert saved_findings
    assert "trace" in saved_findings[0]


def _phase5_finding(vuln_type: str = "command_injection", file_path: str = "app.py") -> Finding:
    return Finding(
        id=f"finding-{vuln_type}",
        vulnerability_type=vuln_type,
        severity="high",
        title=vuln_type,
        description="phase 5 verification fixture",
        file_path=file_path,
        line_start=3,
        source="request.args",
        sink="os.system" if vuln_type == "command_injection" else "sink",
        function_name="handler",
        trigger_conditions=["attacker controls input"],
        exploit_payloads=["; id"],
        evidence=["static source-to-sink evidence"],
        should_verify=True,
    )


def test_phase5_static_verifier_uses_trace_and_constrains_llm(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("def handler(value):\n    return os.system(value)\n", encoding="utf-8")
    finding = _phase5_finding()
    finding.line_start = 2
    finding.risk_domain = "source_code"
    finding.candidate_id = "candidate-1"
    finding.slice_id = "slice-1"
    finding.dangerous_function_id = "danger-1"
    candidate = VulnerabilityCandidate(
        id="candidate-1",
        slice_id="slice-1",
        title="command injection",
        vulnerability_type="command_injection",
        severity="high",
        file_path="app.py",
        line_start=2,
        description="source reaches shell",
        source="request.args",
        sink="os.system",
    )
    program_slice = ProgramSlice(
        id="slice-1",
        dangerous_function_id="danger-1",
        file_path="app.py",
        line_start=2,
        function_name="handler",
        source="request.args",
        sink="os.system",
        data_flow=["request.args -> value -> os.system"],
        missing_guards=["shell escaping"],
    )
    dangerous = DangerousFunction(
        id="danger-1",
        file_path="app.py",
        line_start=2,
        function_name="handler",
        dangerous_api="os.system",
        sink="os.system",
        snippet="return os.system(value)",
        language="Python",
        category="command",
        confidence=0.9,
    )

    class ReviewLLM:
        enabled = True

        def chat(self, *_args, **_kwargs):
            content = (
                '[{"finding_id":"finding-command_injection",'
                '"verdict":"plausible","reachability":"reachable",'
                '"reason":"trace is coherent"}]'
            )
            return type("Resp", (), {"ok": True, "content": content, "error": ""})()

    verifier = StaticVerifier(ReviewLLM())
    result = verifier.verify(tmp_path, finding, candidate, program_slice, dangerous, [])
    verifier.review_batch([finding], [result])

    assert result.static_status == "plausible"
    assert result.reachability == "reachable"
    assert result.dynamic_eligible is True
    assert result.rule_checks["trace_linked"] is True
    assert result.llm_review["status"] == "completed"


def test_phase5_static_verifier_reclassifies_source_exec_sink_from_environment(tmp_path: Path):
    source_dir = tmp_path / "vulnerabilities" / "exec" / "source"
    source_dir.mkdir(parents=True)
    php_file = source_dir / "high.php"
    php_file.write_text(
        "<?php\n$target = $_REQUEST['ip'];\n$cmd = shell_exec('ping -c 4 ' . $target);\n",
        encoding="utf-8",
    )
    finding = _phase5_finding("other", "vulnerabilities/exec/source/high.php")
    finding.line_start = 3
    finding.source = "tool_verified(semgrep)"
    finding.sink = "php.lang.security.exec-use.exec-use"
    finding.risk_domain = "environment"
    finding.should_verify = False
    finding.needs_verification = False
    finding.evidence = [
        "tool_verified(semgrep); sink=php.lang.security.exec-use.exec-use",
        "$cmd = shell_exec( 'ping  -c 4 ' . $target );",
    ]

    result = StaticVerifier().verify(tmp_path, finding)

    assert finding.vulnerability_type == "command_injection"
    assert finding.risk_domain == "source_code"
    assert finding.should_verify is True
    assert finding.needs_verification is True
    assert result.risk_domain == "source_code"
    assert result.static_status in {"plausible", "weak_static_proof"}
    assert result.dynamic_eligible is True


def test_phase5_non_source_findings_are_static_only_without_poc(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("demo==1.0\n", encoding="utf-8")
    finding = _phase5_finding("dependency_vulnerability", "requirements.txt")
    finding.risk_domain = "dependency"
    profile = ProjectProfile(root=str(tmp_path), languages={"Python": 1})
    output = tmp_path / "report"

    result = VerificationAgent().verify(tmp_path, [finding], output, profile)[0]

    assert result.status == "static_only"
    assert result.dynamic_attempted is False
    assert result.static_verification["static_status"] == "static_only"
    assert result.dynamic_verification["blocked_reason"] == "risk_domain_static_only"
    assert not (output / "pocs").exists()
    assert not (output / "exploits").exists()


def test_phase5_dynamic_planner_applies_static_gate_and_precise_block_reason(tmp_path: Path):
    finding = _phase5_finding("unsafe_memory_copy", "main.cpp")
    finding.risk_domain = "source_code"
    profile = ProjectProfile(root=str(tmp_path), languages={"C++": 1})
    environment = EnvironmentManager().inspect(tmp_path, profile, finding)
    static_result = StaticVerifier().verify(tmp_path, finding)
    static_result.static_status = "plausible"
    static_result.dynamic_eligible = True
    build = BuildDecision(False, "Native project detected; auto-build is disabled.", status="blocked")

    plan = DynamicPlanner().plan(
        tmp_path,
        profile,
        finding,
        static_result,
        environment,
        build_decision=build,
    )

    assert plan.runtime_type == "cpp_harness"
    assert plan.status == "blocked"
    assert plan.blocked_reason == "build_disabled"


def test_phase5_dynamic_planner_validates_llm_tactics(tmp_path: Path):
    class PlannerLLM:
        enabled = True

        def chat(self, *_args, **_kwargs):
            content = (
                '[{"finding_id":"finding-command_injection",'
                '"runtime_type":"cpp_cli","build_strategy":"cmake_build",'
                '"poc_strategy":"malformed_file","oracle":"asan_crash",'
                '"rationale":"try an incompatible native strategy"}]'
            )
            return type("Resp", (), {"ok": True, "content": content, "error": ""})()

    finding = _phase5_finding()
    finding.risk_domain = "source_code"
    profile = ProjectProfile(root=str(tmp_path), languages={"Python": 1})
    environment = EnvironmentManager().inspect(tmp_path, profile, finding)
    static_result = StaticVerifier().verify(tmp_path, finding)
    static_result.static_status = "plausible"
    static_result.dynamic_eligible = True
    planner = DynamicPlanner(PlannerLLM())
    plan = planner.plan(tmp_path, profile, finding, static_result, environment)

    planner.review_batch(profile, [(finding, static_result, environment, plan)])

    assert plan.runtime_type == "python_test"
    assert plan.build_strategy == "no_build_required"
    assert plan.poc_strategy == "unit_test"
    assert plan.oracle == "stderr_marker"
    assert set(plan.planner_review["rejected_fields"]) >= {
        "runtime_type",
        "build_strategy",
        "poc_strategy",
        "oracle",
    }


def test_phase5_dynamic_budget_executes_only_topk(tmp_path: Path, monkeypatch):
    import agentic_code_audit.agents.verification as verification_module

    monkeypatch.setattr(
        verification_module.shutil,
        "which",
        lambda name: None if name == "docker" else sys.executable,
    )
    findings = []
    for index in range(3):
        path = tmp_path / f"app{index}.py"
        path.write_text("import os\ndef handler(value):\n    return os.system(value)\n", encoding="utf-8")
        finding = _phase5_finding("command_injection", path.name)
        finding.id = f"finding-{index}"
        finding.line_start = 3
        finding.risk_domain = "source_code"
        finding.director_priority = 10 - index
        findings.append(finding)

    results = VerificationAgent().verify(
        tmp_path,
        findings,
        tmp_path / "report",
        ProjectProfile(root=str(tmp_path), languages={"Python": 1}),
        strategy={"validated": True},
        max_dynamic_verifications=1,
    )

    assert sum(1 for item in results if item.dynamic_attempted) == 1
    assert sum(
        1
        for item in results
        if item.dynamic_verification.get("blocked_reason") == "dynamic_budget_exhausted"
    ) == 2
    assert len(list((tmp_path / "report" / "pocs").iterdir())) == 1


def test_phase5_environment_manager_identifies_project_shapes(tmp_path: Path, monkeypatch):
    import agentic_code_audit.agents.verification as verification_module

    monkeypatch.setattr(verification_module.shutil, "which", lambda name: f"/bin/{name}" if name in {"python", "node", "npm"} else None)
    manager = EnvironmentManager()

    cpp = tmp_path / "cpp"
    cpp.mkdir()
    (cpp / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.20)\n", encoding="utf-8")
    cpp_profile = ProjectProfile(root=str(cpp), languages={"C++": 1}, build_entries=[{"type": "cmake"}])
    cpp_env = manager.inspect(cpp, cpp_profile, _phase5_finding("unsafe_memory_copy", "main.cpp"))
    assert cpp_env.runtime_type == "cpp_cli"
    assert "cmake" in cpp_env.build_systems
    assert any("missing tool" in gap for gap in cpp_env.environment_gaps)

    py = tmp_path / "py"
    py.mkdir()
    (py / "app.py").write_text("import os\n\ndef handler(x):\n    return os.system(x)\n", encoding="utf-8")
    py_env = manager.inspect(py, ProjectProfile(root=str(py), languages={"Python": 1}), _phase5_finding())
    assert py_env.runtime_type == "python_test"
    assert py_env.available_tools["python"]

    node = tmp_path / "node"
    node.mkdir()
    (node / "package.json").write_text("{}", encoding="utf-8")
    node_env = manager.inspect(node, ProjectProfile(root=str(node), languages={"JavaScript": 1}), _phase5_finding("command_injection", "app.js"))
    assert node_env.runtime_type == "node_test"
    assert node_env.available_tools["node"]

    lib_profile = ProjectProfile(root=str(tmp_path), project_type="library", library_entries=[{"name": "lib"}])
    lib_env = manager.inspect(tmp_path, lib_profile, _phase5_finding("logic_bug", "lib.txt"))
    assert lib_env.runtime_type == "library_harness"


def test_phase5_runtime_manager_selects_expected_runtime_types(tmp_path: Path):
    manager = RuntimeManager()
    profile = ProjectProfile(root=str(tmp_path), languages={"Python": 1})
    env = EnvironmentManager().inspect(tmp_path, profile, _phase5_finding())

    http_finding = _phase5_finding("path_traversal")
    http_finding.route = "GET /download"
    assert manager.decide(tmp_path, profile, http_finding, env, "http://127.0.0.1:1").runtime_type == "http_service"

    dep_finding = _phase5_finding("dependency_vulnerability", "requirements.txt")
    assert manager.decide(tmp_path, profile, dep_finding, env).runtime_type == "dependency_only"

    cpp_env = EnvironmentManager().inspect(tmp_path, ProjectProfile(root=str(tmp_path), languages={"C++": 1}), _phase5_finding("unsafe_memory_copy", "main.cpp"))
    assert manager.decide(tmp_path, profile, _phase5_finding("unsafe_memory_copy", "main.cpp"), cpp_env).runtime_type == "cpp_harness"
    assert manager.decide(tmp_path, profile, _phase5_finding(), env).runtime_type == "python_test"


def test_phase5_build_manager_blocks_missing_native_tools(tmp_path: Path, monkeypatch):
    (tmp_path / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.20)\n", encoding="utf-8")
    finding = _phase5_finding("unsafe_memory_copy", "main.cpp")
    profile = ProjectProfile(root=str(tmp_path), languages={"C++": 1})
    env = EnvironmentManager().inspect(tmp_path, profile, finding)

    manager = BuildManager()
    monkeypatch.setattr(manager, "_sandbox_reachable", lambda: True)
    monkeypatch.setattr(manager, "_sandbox_has_any_tool", lambda _tools: False)
    decision, executable = manager.prepare(
        tmp_path, profile, finding, env, tmp_path / "out", auto_build_native=True
    )
    assert executable is None
    assert decision.status == "blocked"
    assert decision.missing_tools
    assert decision.install_hints


def test_phase6_sandbox_executor_blocks_without_docker_and_records_artifacts(tmp_path: Path, monkeypatch):
    import agentic_code_audit.agents.verification as verification_module

    monkeypatch.setattr(verification_module.shutil, "which", lambda name: None if name == "docker" else sys.executable)
    plan = HarnessPlan(
        method="test harness",
        language="python",
        script='print("[DETECTED] command injection sentinel")\n',
        command=["python", "/workspace/harness.py"],
        oracle="[DETECTED] in stdout",
        explanation="unit test",
    )

    outcome = SandboxExecutor().execute(plan, tmp_path / "sandbox")
    assert outcome.local_fallback is False
    assert outcome.status == "blocked"
    assert outcome.checker_details["blocked_reason"] == "missing_docker"
    assert (tmp_path / "sandbox" / "command.json").exists()
    assert (tmp_path / "sandbox" / "stdout.log").exists()
    assert any(path.name == "changed_files.json" for path in outcome.artifact_paths)


def test_phase6_verification_container_is_networkless_and_limited(tmp_path: Path, monkeypatch):
    import agentic_code_audit.agents.verification as verification_module

    class Completed:
        returncode = 0
        stdout = "[DETECTED] command injection sentinel\n"
        stderr = ""

    monkeypatch.setattr(verification_module.shutil, "which", lambda name: "docker" if name == "docker" else None)
    monkeypatch.setattr(verification_module.subprocess, "run", lambda *_args, **_kwargs: Completed())
    executor = SandboxExecutor(compose_container="audit-sandbox")
    monkeypatch.setattr(executor, "_container_running", lambda _docker: True)
    plan = HarnessPlan(
        method="test harness",
        language="python",
        script='print("[DETECTED] command injection sentinel")\n',
        command=["python", "/workspace/harness.py"],
        oracle="marker",
        explanation="unit test",
    )

    outcome = executor.execute(plan, tmp_path / "sandbox")

    assert outcome.status == "verified"
    assert outcome.sandbox_command[:3] == ["docker", "run", "--rm"]
    assert outcome.sandbox_command[outcome.sandbox_command.index("--network") + 1] == "none"
    assert outcome.sandbox_command[outcome.sandbox_command.index("--memory") + 1] == "1g"
    assert outcome.sandbox_command[outcome.sandbox_command.index("--cpus") + 1] == "1"
    assert outcome.sandbox_command[outcome.sandbox_command.index("--volumes-from") + 1] == "audit-sandbox"


def test_phase5_checkers_require_real_oracle_evidence():
    empty = CheckerOutcome(status="uncertain", summary="", exit_code=0)
    assert MemorySafetyChecker().check(empty).status != "verified"

    memory = CheckerOutcome(status="uncertain", summary="", exit_code=1, stderr_excerpt="AddressSanitizer: heap-buffer-overflow")
    assert MemorySafetyChecker().check(memory).status == "verified"

    command = CheckerOutcome(status="uncertain", summary="", exit_code=0, stdout_excerpt="[DETECTED] command injection sentinel")
    assert CommandInjectionChecker().check(command).status == "verified"

    traversal = CheckerOutcome(status="uncertain", summary="", exit_code=0, stdout_excerpt="TRAVERSAL_SENTINEL")
    assert PathTraversalChecker().check(traversal).status == "verified"

    sql = CheckerOutcome(status="uncertain", summary="", exit_code=0, stdout_excerpt="rows_bypassed")
    assert SQLInjectionChecker().check(sql).status == "verified"

    dependency = CheckerOutcome(status="uncertain", summary="", evidence=["OSV affected range"])
    assert DependencyChecker().check(dependency).status == "partially_verified"


def test_phase5_exploit_agent_generates_records_for_blocked_and_verified(tmp_path: Path):
    finding = _phase5_finding()
    poc_dir = tmp_path / "poc"
    poc_dir.mkdir()
    poc = poc_dir / "poc_manual.md"
    poc.write_text("# poc\n", encoding="utf-8")
    plan = PocPlan(
        finding=finding,
        analysis=PocAnalysis("valid", "manual_harness", "oracle", "details"),
        poc_dir=poc_dir,
        poc_path=poc,
    )

    blocked = ExploitAgent().generate(plan, CheckerOutcome(status="blocked", summary="missing docker"), tmp_path)
    verified = ExploitAgent().generate(plan, CheckerOutcome(status="verified", summary="sentinel matched"), tmp_path)
    assert any(path.name == "exploit.md" for path in blocked)
    assert any(path.name.startswith("replay") for path in verified)


def test_phase5_verification_to_store_persistence_end_to_end(tmp_path: Path, monkeypatch):
    import agentic_code_audit.agents.verification as verification_module

    monkeypatch.setattr(verification_module.shutil, "which", lambda name: None if name == "docker" else sys.executable)
    target = tmp_path / "project"
    target.mkdir()
    (target / "app.py").write_text("import os\n\ndef handler(x):\n    return os.system(x)\n", encoding="utf-8")
    profile = ProjectProfile(root=str(target), languages={"Python": 1})
    finding = _phase5_finding()
    finding.code_snippet = "return os.system(x)"

    verification_results = VerificationAgent().verify(target, [finding], tmp_path / "report", profile)
    assert verification_results
    result = verification_results[0]
    assert result.runtime_type == "python_test"
    assert result.strategy
    assert result.environment
    assert result.execution
    assert result.evidence_artifact_ids
    assert result.exploit_artifact_ids
    assert result.local_fallback is False
    assert result.status == "blocked"
    assert result.blocked_reason == "missing_docker"
    assert result.static_verification["static_status"] == "plausible"
    assert result.dynamic_verification["status"] == "planned"
    assert result.checker_verdict["status"] == result.status
    assert result.dynamic_attempted is True

    store = AuditStore(tmp_path / "audit.sqlite3")
    task_id = store.create_task(str(target), "full", "deepseek-v4-pro", "", False)
    json_report = tmp_path / "audit-report.json"
    markdown_report = tmp_path / "audit-report.md"
    json_report.write_text("{}", encoding="utf-8")
    markdown_report.write_text("# report\n", encoding="utf-8")
    report = AuditReport(
        input_source=InputSource(original=str(target), kind="local", local_path=str(target)),
        target=str(target),
        created_at="2026-01-01T00:00:00+00:00",
        profile=profile,
        semantic_index=SemanticIndex(),
        tool_results=[],
        dangerous_functions=[],
        program_slices=[],
        candidates=[],
        findings=[finding],
        verification_results=verification_results,
    )

    store.save_report(task_id, report, json_report, markdown_report)
    detail = store.get_finding(task_id, finding.id)
    assert detail is not None
    assert detail["verification"]["runtime_type"] == "python_test"
    assert detail["verification"]["evidence_artifact_ids"]
    assert detail["verification"]["exploit_artifact_ids"]
    assert detail["verification"]["static_verification"]["static_status"] == "plausible"
    assert detail["verification"]["dynamic_verification"]["status"] == "planned"
    assert detail["verification"]["checker_verdict"]["status"] == result.status


def test_phase6_mining_director_list_directory_records_success_and_errors(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
    director = MiningDirector(FakeLLM())  # type: ignore[arg-type]
    director._exploration_tools = CodeExplorationTools(tmp_path)

    assert "[D] src" in director._tool_list_directory(".")
    assert director._tool_list_directory("missing").startswith("[ERROR]")
    assert director._tool_list_directory("../outside").startswith("[ERROR]")
    assert [item["success"] for item in director._exploration_tools.log] == [True, False, False]


def test_phase6_static_verifier_keeps_non_direct_sink_as_weak(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "import os\n\ndef handler():\n    return os.system('fixed')\n",
        encoding="utf-8",
    )
    finding = _phase5_finding()
    finding.code_snippet = "return os.system('fixed')"

    result = StaticVerifier().verify(tmp_path, finding)

    assert result.static_status == "weak_static_proof"
    assert result.rule_checks["direct_parameter_to_sink"] is False


def test_phase6_tool_availability_is_shared_with_planner(tmp_path: Path, monkeypatch):
    import agentic_code_audit.tools.runner as runner_module

    class Completed:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    runner = ToolRunner(make_settings(), sandbox_container="audit-sandbox")
    monkeypatch.setattr(runner, "_sandbox_available", lambda: True)

    def fake_run(command, **_kwargs):
        if "which" in command:
            return Completed(stdout="/usr/bin/cppcheck\n")
        return Completed(stdout="Cppcheck 2.14\n")

    monkeypatch.setattr(runner_module.subprocess, "run", fake_run)
    availability = runner.check_tool("cppcheck")
    assert runner.registry.get("ctags").capability == "code-navigation"
    planner = ToolPlanner(
        runner.registry,
        runner.env,
        availability_provider=lambda: [availability],
    )
    (tmp_path / "main.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
    profile = ProjectProfile(root=str(tmp_path), languages={"C++": 1})
    recommendations = planner.recommend_tools(
        "VulnerabilityMiningAgent", "mine_vulnerabilities", profile, tmp_path
    )

    cppcheck = next(item for item in recommendations if item.name == "cppcheck")
    assert cppcheck.available is True
    assert availability.execution_location == "sandbox"
    assert availability.container == "audit-sandbox"
    assert availability.network_policy == "none"


def test_phase7_native_build_authorization_precedes_sandbox_capability(tmp_path: Path, monkeypatch):
    (tmp_path / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.20)\n", encoding="utf-8")
    profile = ProjectProfile(root=str(tmp_path), languages={"C++": 1})
    finding = _phase5_finding("unsafe_memory_copy", "main.cpp")
    environment = EnvironmentManager().inspect(tmp_path, profile, finding)
    manager = BuildManager()
    monkeypatch.setattr(manager, "_sandbox_reachable", lambda: True)
    monkeypatch.setattr(manager, "_sandbox_has_any_tool", lambda _tools: True)

    decision, executable = manager.prepare(
        tmp_path, profile, finding, environment, tmp_path / "out", auto_build_native=False
    )

    assert executable is None
    assert decision.blocked_reason == "build_disabled"
    assert decision.should_attempt is False


def test_phase7_build_failure_reasons_are_stable():
    offline = BuildManager(build_network_enabled=False)
    assert offline._classify_build_failure("", "Could not resolve host: example.test") == "network_disabled"
    assert offline._classify_build_failure("", "Could NOT find ZLIB (missing: ZLIB_LIBRARY)") == "missing_dependency"
    assert offline._classify_build_failure("", "compiler terminated") == "build_failed"


def test_phase8_openvpn_like_project_prefers_autotools_over_cmake(tmp_path: Path):
    (tmp_path / "CMakeLists.txt").write_text('message(FATAL_ERROR "On Unix use autoconfig")\n', encoding="utf-8")
    (tmp_path / "configure.ac").write_text("AC_INIT([demo], [1.0])\n", encoding="utf-8")
    (tmp_path / "Makefile.am").write_text("bin_PROGRAMS = demo\n", encoding="utf-8")
    profile = ProjectProfile(root=str(tmp_path), languages={"C": 1})
    finding = _phase5_finding("unsafe_c_string_api", "src/misc.c")

    environment = EnvironmentManager().inspect(tmp_path, profile, finding)

    assert environment.build_systems[:2] == ["autotools", "cmake"]


def test_phase8_cmake_wrong_build_system_reason_is_stable():
    manager = BuildManager(build_network_enabled=False)
    assert manager._classify_build_failure("", "CMake is only used for Windows; use autoconfig on Unix") == "wrong_build_system"


def test_phase8_autotools_requires_bootstrap_tools():
    manager = BuildManager()
    calls: list[list[str]] = []

    def fake_has_any(tools: list[str]) -> bool:
        calls.append(tools)
        return True

    manager._sandbox_has_any_tool = fake_has_any  # type: ignore[method-assign]

    assert manager._missing_build_tools("autotools") == []
    assert ["autoreconf", "autoconf"] in calls
    assert ["automake", "aclocal"] in calls
    assert ["libtoolize", "libtool"] in calls


def test_phase8_dynamic_planner_accepts_structured_recipe(tmp_path: Path):
    class PlannerLLM:
        enabled = True

        def chat(self, *_args, **_kwargs):
            content = json.dumps(
                [
                    {
                        "finding_id": "finding-command_injection",
                        "runtime_type": "python_test",
                        "build_strategy": "no_build_required",
                        "poc_strategy": "unit_test",
                        "oracle": "stderr_marker",
                        "rationale": "call the function with a sentinel payload",
                        "verification_recipe": {
                            "target_function": "run",
                            "source": "request.args",
                            "sink": "subprocess",
                            "preconditions": ["payload reaches command string"],
                            "preferred_build": "no_build_required",
                            "runtime_entry": "python_test",
                            "fallback_harness": "pytest-style unit harness",
                            "micro_proof": "direct subprocess sentinel proof",
                            "oracle": "stderr_marker",
                            "expected_signal": "sentinel in stderr",
                            "limitations": ["no service runtime"],
                        },
                    }
                ]
            )
            return type("Resp", (), {"ok": True, "content": content, "error": ""})()

    finding = _phase5_finding()
    finding.risk_domain = "source_code"
    profile = ProjectProfile(root=str(tmp_path), languages={"Python": 1})
    environment = EnvironmentManager().inspect(tmp_path, profile, finding)
    static_result = StaticVerifier().verify(tmp_path, finding)
    static_result.static_status = "plausible"
    static_result.dynamic_eligible = True
    planner = DynamicPlanner(PlannerLLM())
    plan = planner.plan(tmp_path, profile, finding, static_result, environment)

    planner.review_batch(profile, [(finding, static_result, environment, plan)])

    assert plan.verification_recipe["source_kind"] == "llm_review"
    assert plan.verification_recipe["target_function"] == "run"
    assert "verification_recipe" in plan.planner_review["accepted_fields"]


def test_phase8_blocked_runtime_uses_partial_proof_without_verified_status(tmp_path: Path):
    class FakeSandbox:
        def execute(self, harness, work_dir):
            work_dir.mkdir(parents=True, exist_ok=True)
            return CheckerOutcome(
                status="verified",
                summary="marker matched",
                stdout_excerpt="[DETECTED] partial dynamic proof",
                stderr_excerpt="",
                exit_code=0,
                sandbox_command=["docker", "run", "--network", "none", "sh", "/workspace/harness.sh"],
                artifact_paths=[work_dir / "harness.sh"],
                execution={"command": ["docker", "run"], "exit_code": 0},
                checker_details={"checker": "SandboxExecutor"},
            )

    finding = _phase5_finding("unsafe_c_string_api", "main.c")
    finding.risk_domain = "source_code"
    profile = ProjectProfile(root=str(tmp_path), languages={"C": 1})
    environment = EnvironmentManager().inspect(tmp_path, profile, finding)
    static_result = StaticVerifier().verify(tmp_path, finding)
    static_result.static_status = "plausible"
    static_result.dynamic_eligible = True
    dynamic_plan = DynamicPlanner().plan(
        tmp_path,
        profile,
        finding,
        static_result,
        environment,
        build_decision=BuildDecision(True, "build failed", build_system="autotools", status="blocked", blocked_reason="build_failed"),
    )
    poc_dir = tmp_path / "poc"
    poc_dir.mkdir()
    poc_plan = PocPlan(
        finding=finding,
        analysis=PocAnalysis("valid", "cpp_harness", "asan_crash", "details"),
        poc_dir=poc_dir,
        poc_path=poc_dir / "poc_input.bin",
    )

    outcome = RuntimeManager(sandbox=FakeSandbox()).execute_plan(
        tmp_path,
        profile,
        poc_plan,
        dynamic_plan,
        "",
        VerificationPlanner(),
    )

    assert outcome.status == "partial_dynamic_proof"
    assert outcome.status != "verified"
    assert outcome.checker_details["proof_level"] == "micro_proof"
    assert outcome.checker_details["fallback_attempts"][0]["status"] == "partial_dynamic_proof"


def test_phase8_verification_agent_routes_blocked_build_to_partial_proof(tmp_path: Path, monkeypatch):
    import agentic_code_audit.agents.verification as verification_module

    (tmp_path / "main.c").write_text("void f(char *s) { char d[8]; strcpy(d, s); }\n", encoding="utf-8")
    finding = _phase5_finding("unsafe_c_string_api", "main.c")
    finding.risk_domain = "source_code"
    finding.source = "stdin"
    finding.sink = "strcpy"
    profile = ProjectProfile(root=str(tmp_path), languages={"C": 1})
    monkeypatch.setattr(verification_module.shutil, "which", lambda name: "docker" if name == "docker" else sys.executable)

    agent = VerificationAgent()
    monkeypatch.setattr(agent.environment_manager, "inspect", lambda *_args, **_kwargs: EnvironmentProfile(
        runtime_type="cpp_cli",
        languages={"C": 1},
        project_type="cli",
        build_systems=["autotools"],
        can_execute=True,
    ))
    monkeypatch.setattr(agent.build_manager, "prepare", lambda *_args, **_kwargs: (
        BuildDecision(True, "failed", build_system="autotools", status="blocked", blocked_reason="build_failed"),
        None,
    ))
    monkeypatch.setattr(agent.sandbox, "execute", lambda harness, work_dir: CheckerOutcome(
        status="verified",
        summary="partial marker",
        stdout_excerpt="[DETECTED] partial dynamic proof",
        exit_code=0,
        sandbox_command=["docker", "run", "--network", "none"],
        checker_details={"checker": "SandboxExecutor"},
    ))

    result = agent.verify(tmp_path, [finding], tmp_path / "out", profile, enable_native_build=True)[0]

    assert result.status == "partial_dynamic_proof"
    assert result.proof_level == "micro_proof"
    assert result.fallback_attempts


def test_phase8_native_stdin_poc_uses_text_payload_plan(tmp_path: Path):
    finding = _phase5_finding("unsafe_c_string_api", "main.c")
    finding.source = "stdin"
    finding.sink = "strcpy"
    finding.trigger_conditions = ["stdin"]
    finding.exploit_payloads = ["username\n" + ("A" * 64)]
    analysis = PocAnalysis("valid", "cpp_cli", "asan_crash", "details")
    plan = {
        "verification_recipe": {
            "payload_format": "stdin_text",
            "payloads": ["NEED-OK|Auth|user", "A" * 128],
            "stdin_script": "NEED-OK|Auth|user\n" + ("A" * 128),
            "execution_steps": ["pipe poc_input.txt to stdin"],
        }
    }

    poc = PocGenerator().generate(tmp_path, finding, analysis, tmp_path / "out", structured_plan=plan)

    assert poc.poc_path.name == "poc_input.txt"
    assert "NEED-OK|Auth|user" in poc.poc_path.read_text(encoding="utf-8")
    assert plan["poc_payload_plan"]["format"] == "stdin_text"


def test_phase8_native_stdin_fallback_avoids_all_a_payload(tmp_path: Path):
    finding = _phase5_finding("unsafe_c_string_api", "main.c")
    finding.source = "stdin"
    finding.sink = "strcpy"
    finding.trigger_conditions = ["stdin"]
    finding.exploit_payloads = ["A" * 4096]
    analysis = PocAnalysis("valid", "cpp_cli", "asan_crash", "details")
    structured_plan = {"verification_recipe": {"payload_format": "generic_overflow_probe"}}

    poc = PocGenerator().generate(tmp_path, finding, analysis, tmp_path / "out", structured_plan=structured_plan)
    content = poc.poc_path.read_text(encoding="utf-8")

    assert poc.poc_path.name == "poc_input.txt"
    assert "待补充 PoC 输入模板" in content
    assert "sink=strcpy" in content
    assert "payload=<由 LLM 或人工根据目标协议补充可运行输入>" in content
    assert content.strip("A\n ") != ""
    bug_report = (tmp_path / "out" / "pocs" / finding.id / "bug_report.md").read_text(encoding="utf-8")
    assert "待补充 PoC 输入模板" in bug_report
    assert "sink=strcpy" in bug_report
    assert ("- `" + ("A" * 128)) not in bug_report
    assert structured_plan["poc_payload_plan"]["source"] == "template_fallback"
    assert structured_plan["poc_payload_plan"]["is_template"] is True


def test_phase8_llm_payload_planner_can_replace_generic_overflow_probe(tmp_path: Path):
    class PayloadLLM:
        enabled = True

        def chat(self, *_args, **_kwargs):
            content = json.dumps({
                "format": "stdin_text",
                "payloads": ["username", "password"],
                "stdin_script": "username\npassword\n",
                "execution_steps": ["pipe into stdin"],
                "expected_signal": "asan_crash",
                "limitations": ["requires focused harness"],
            })
            return type("Resp", (), {"ok": True, "content": content, "error": ""})()

    finding = _phase5_finding("unsafe_c_string_api", "main.c")
    finding.source = "stdin"
    finding.sink = "strcpy"
    finding.exploit_payloads = ["A" * 4096]
    analysis = PocAnalysis("valid", "cpp_cli", "asan_crash", "details")
    structured_plan = {"verification_recipe": {"payload_format": "generic_overflow_probe"}}

    poc = PocGenerator(PayloadLLM()).generate(tmp_path, finding, analysis, tmp_path / "out", structured_plan=structured_plan)

    assert poc.poc_path.name == "poc_input.txt"
    assert "username" in poc.poc_path.read_text(encoding="utf-8")
    assert structured_plan["poc_payload_plan"]["source"] == "llm_payload_planner"


def test_phase8_poc_generation_prefers_llm_over_recipe_payload(tmp_path: Path):
    class PayloadLLM:
        enabled = True

        def chat(self, *_args, **_kwargs):
            content = json.dumps({
                "format": "stdin_text",
                "payloads": ["llm-protocol-field=owned"],
                "stdin_script": "llm-protocol-field=owned\n",
                "execution_steps": ["pipe LLM-generated input into the harness"],
                "expected_signal": "checker marker",
            })
            return type("Resp", (), {"ok": True, "content": content, "error": ""})()

    finding = _phase5_finding("unsafe_c_string_api", "main.c")
    finding.source = "stdin"
    finding.sink = "strcpy"
    analysis = PocAnalysis("valid", "cpp_cli", "asan_crash", "details")
    structured_plan = {
        "verification_recipe": {
            "payload_format": "stdin_text",
            "payloads": ["recipe-should-not-win"],
            "stdin_script": "recipe-should-not-win\n",
        }
    }

    poc = PocGenerator(PayloadLLM()).generate(tmp_path, finding, analysis, tmp_path / "out", structured_plan=structured_plan)

    content = poc.poc_path.read_text(encoding="utf-8")
    assert "llm-protocol-field=owned" in content
    assert "recipe-should-not-win" not in content
    assert structured_plan["poc_payload_plan"]["source"] == "llm_payload_planner"


def test_phase8_llm_payload_planner_writes_runnable_harness_artifacts(tmp_path: Path):
    class PayloadLLM:
        enabled = True

        def chat(self, *_args, **_kwargs):
            content = json.dumps({
                "format": "stdin_text",
                "payloads": ["username=admin\npassword=long-boundary-value\n"],
                "stdin_script": "username=admin\npassword=long-boundary-value\n",
                "harness_language": "c",
                "harness_filename": "openvpn_userpass_harness.c",
                "harness_code": "#include <stdio.h>\nint main(void) { puts(\"local harness\"); return 0; }\n",
                "run_commands": ["${CC:-cc} -fsanitize=address,undefined poc_harness.c -o poc_harness", "./poc_harness < poc_input.txt"],
                "poc_explanation": "Feed a username/password style record into the focused user-pass harness.",
                "execution_steps": ["compile poc_harness.c", "run with poc_input.txt"],
                "expected_signal": "asan_crash",
                "limitations": ["focused harness"],
            })
            return type("Resp", (), {"ok": True, "content": content, "error": ""})()

    finding = _phase5_finding("unsafe_c_string_api", "main.c")
    finding.source = "stdin"
    finding.sink = "strcpy"
    finding.exploit_payloads = ["A" * 4096]
    analysis = PocAnalysis("valid", "cpp_cli", "asan_crash", "details")
    structured_plan = {"verification_recipe": {"payload_format": "generic_overflow_probe"}}

    poc = PocGenerator(PayloadLLM()).generate(tmp_path, finding, analysis, tmp_path / "out", structured_plan=structured_plan)
    poc_dir = tmp_path / "out" / "pocs" / finding.id

    assert poc.poc_path.name == "poc_input.txt"
    assert (poc_dir / "poc_harness.c").exists()
    assert (poc_dir / "run_poc.sh").exists()
    assert (poc_dir / "poc_explanation.md").exists()
    assert "username=admin" in poc.poc_path.read_text(encoding="utf-8")
    assert "local harness" in (poc_dir / "poc_harness.c").read_text(encoding="utf-8")
    assert "Feed a username/password" in (poc_dir / "poc_explanation.md").read_text(encoding="utf-8")
    assert any(Path(path).name == "poc_harness.c" for path in poc.generated_artifacts)
    assert any(Path(path).name == "run_poc.sh" for path in poc.generated_artifacts)


def test_phase8_llm_all_a_payload_plan_is_rejected(tmp_path: Path):
    class PayloadLLM:
        enabled = True

        def chat(self, *_args, **_kwargs):
            content = json.dumps({
                "format": "stdin_input",
                "payloads": ["A" * 512],
                "stdin_script": "echo 'AAAAAAAA...' | ./harness",
                "execution_steps": ["pipe into harness"],
                "limitations": ["generic overflow probe"],
            })
            return type("Resp", (), {"ok": True, "content": content, "error": ""})()

    finding = _phase5_finding("unsafe_c_string_api", "main.c")
    finding.source = "stdin"
    finding.sink = "strcpy"
    finding.trigger_conditions = ["stdin"]
    finding.exploit_payloads = ["A" * 4096]
    analysis = PocAnalysis("valid", "cpp_cli", "asan_crash", "details")
    structured_plan = {"verification_recipe": {"payload_format": "generic_overflow_probe"}}

    poc = PocGenerator(PayloadLLM()).generate(tmp_path, finding, analysis, tmp_path / "out", structured_plan=structured_plan)
    content = poc.poc_path.read_text(encoding="utf-8")

    assert poc.poc_path.name == "poc_input.txt"
    assert structured_plan["poc_payload_plan"]["source"] == "template_fallback"
    assert "待补充 PoC 输入模板" in content
    assert "echo 'AAAAAAAA...'" not in content
    bug_report = (tmp_path / "out" / "pocs" / finding.id / "bug_report.md").read_text(encoding="utf-8")
    assert "待补充 PoC 输入模板" in bug_report
    assert "echo 'AAAAAAAA...'" not in bug_report


def test_phase8_llm_all_a_payload_with_harness_keeps_code_and_repairs_input(tmp_path: Path):
    class PayloadLLM:
        enabled = True

        def chat(self, *_args, **_kwargs):
            content = json.dumps({
                "format": "stdin_input",
                "payloads": ["A" * 512],
                "stdin_script": "echo 'AAAAAAAA...' | ./harness",
                "harness_language": "c",
                "harness_code": "#include <stdio.h>\nint main(void) { puts(\"kept harness\"); return 0; }\n",
                "execution_steps": ["compile harness"],
                "limitations": ["payload must be repaired"],
            })
            return type("Resp", (), {"ok": True, "content": content, "error": ""})()

    finding = _phase5_finding("unsafe_c_string_api", "main.c")
    finding.source = "stdin"
    finding.sink = "strcpy"
    finding.trigger_conditions = ["stdin"]
    finding.exploit_payloads = ["A" * 4096]
    analysis = PocAnalysis("valid", "cpp_cli", "asan_crash", "details")
    structured_plan = {"verification_recipe": {"payload_format": "generic_overflow_probe"}}

    poc = PocGenerator(PayloadLLM()).generate(tmp_path, finding, analysis, tmp_path / "out", structured_plan=structured_plan)
    poc_dir = tmp_path / "out" / "pocs" / finding.id
    content = poc.poc_path.read_text(encoding="utf-8")

    assert structured_plan["poc_payload_plan"]["source"].endswith("+template")
    assert structured_plan["poc_payload_plan"]["is_template"] is True
    assert "待补充 PoC 输入模板" in content
    assert "echo 'AAAAAAAA...'" not in content
    assert "kept harness" in (poc_dir / "poc_harness.c").read_text(encoding="utf-8")


def test_phase8_verification_planner_uses_llm_recipe_harness(tmp_path: Path):
    finding = _phase5_finding("command_injection", "app.py")
    dynamic_plan = DynamicVerificationPlan(
        finding_id=finding.id,
        status="planned",
        runtime_type="python_test",
        build_strategy="no_build_required",
        poc_strategy="harness",
        oracle="stderr_marker",
        rationale="LLM should choose focused harness.",
        verification_recipe={
            "source_kind": "llm_review",
            "harness_language": "python",
            "harness_filename": "cmd_harness.py",
            "harness_code": "print('[DETECTED] command injection sentinel')\n",
            "stdin_script": "cmd=;id\n",
            "expected_signal": "[DETECTED]",
        },
    )

    harness = VerificationPlanner().plan(finding, tmp_path, dynamic_plan)

    assert harness.strategy == "llm_generated_harness"
    assert "cmd_harness.py" in harness.script
    assert "[DETECTED] command injection sentinel" in harness.script
    assert harness.command == ["sh", "/workspace/harness.sh"]


def test_phase8_fallback_harness_executes_json_values_safely(tmp_path: Path):
    finding = _phase5_finding("command_injection", "missing.php")
    finding.line_end = None
    finding.verification_hint = {"enabled": True, "optional": None}
    finding.code_snippet = "os.system(request.args)"

    harness = VerificationPlanner().plan(finding, tmp_path)
    harness_path = tmp_path / "harness.py"
    harness_path.write_text(harness.script, encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, str(harness_path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
        check=False,
    )

    assert completed.returncode == 0
    assert "[HARNESS] finding finding-command_injection" in completed.stdout
    assert "[EVIDENCE] source, sink, and trigger metadata recorded" in completed.stdout
    assert "[DETECTED]" not in completed.stdout
    assert "NameError" not in completed.stderr


def test_phase8_environment_enables_php_java_go_harness_runtime(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(EnvironmentManager, "_sandbox_reachable", staticmethod(lambda _container="agentic-code-audit-sandbox": False))
    monkeypatch.setattr("agentic_code_audit.agents.verification.shutil.which", lambda tool: f"/usr/bin/{tool}")
    manager = EnvironmentManager()

    php_profile = ProjectProfile(root=str(tmp_path), languages={"PHP": 10}, project_type="library")
    java_profile = ProjectProfile(root=str(tmp_path), languages={"Java": 10}, project_type="library")
    go_profile = ProjectProfile(root=str(tmp_path), languages={"Go": 10}, project_type="library")

    assert manager.inspect(tmp_path, php_profile, _phase5_finding("command_injection", "index.php")).runtime_type == "php_test"
    assert manager.inspect(tmp_path, java_profile, _phase5_finding("deserialization", "Main.java")).runtime_type == "java_test"
    assert manager.inspect(tmp_path, go_profile, _phase5_finding("path_traversal", "main.go")).runtime_type == "go_test"


def test_phase7_cmake_build_uses_ephemeral_offline_container(tmp_path: Path, monkeypatch):
    import agentic_code_audit.agents.verification as verification_module

    class Completed:
        returncode = 0
        stdout = "ok"
        stderr = ""

    calls: list[list[str]] = []

    def fake_run(command, **_kwargs):
        calls.append(command)
        if "cmake --build" in command[-1]:
            executable = tmp_path / ".agentic-build" / "bin" / "exiv2"
            executable.parent.mkdir(parents=True, exist_ok=True)
            executable.write_bytes(b"\x7fELFfixture")
        return Completed()

    monkeypatch.setattr(verification_module.subprocess, "run", fake_run)
    manager = BuildManager(
        sandbox_container="audit-sandbox",
        sandbox_image="audit-sandbox:local",
        build_network_enabled=False,
    )
    decision, executable = manager._build_cmake(tmp_path, tmp_path / "report")

    assert decision.status == "ready"
    assert executable is not None
    assert len(decision.execution) == 2
    assert all(call[call.index("--network") + 1] == "none" for call in calls)
    assert all(call[call.index("--volumes-from") + 1] == "audit-sandbox" for call in calls)


def test_phase7_native_executable_priority_paths(tmp_path: Path):
    executable = tmp_path / ".agentic-build" / "bin" / "exiv2"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"\x7fELFfixture")

    assert PocGenerator()._find_native_executable(tmp_path) == executable


def test_phase7_director_strategy_is_merged_into_dynamic_plan(tmp_path: Path):
    finding = _phase5_finding("unsafe_memory_copy", "main.cpp")
    finding.function_name = "parseImage"
    strategy = MiningStrategy(
        build_attempt=True,
        harness_candidates=["parseImage"],
        parser_entries=["parseImage"],
        suggested_oracles={"parseImage": "asan_crash"},
    )
    hint = VerificationAgent._director_hint_for_finding(finding, strategy)
    static = type(
        "StaticResult",
        (),
        {"risk_domain": "source_code", "static_status": "plausible", "dynamic_eligible": True},
    )()
    profile = ProjectProfile(root=str(tmp_path), languages={"C++": 1})
    environment = EnvironmentManager().inspect(tmp_path, profile, finding)
    plan = DynamicPlanner().plan(
        tmp_path,
        profile,
        finding,
        static,
        environment,
        build_decision=BuildDecision(
            False, "disabled", build_system="cmake", status="blocked", blocked_reason="build_disabled"
        ),
        director_hint=hint,
    )

    assert plan.director_hint["build_attempt"] is True
    assert plan.director_hint["harness_candidate"] == "parseImage"
    assert plan.director_hint["parser_entries"] == ["parseImage"]
    assert plan.oracle == "asan_crash"


def test_phase7_task_native_build_flag_reaches_start_payload(tmp_path: Path, monkeypatch):
    import agentic_code_audit.server as server_module

    store = AuditStore(tmp_path / "api.sqlite3")
    monkeypatch.setattr(server_module, "STORE", store)
    monkeypatch.setattr(server_module.Settings, "load", classmethod(lambda _cls, _root=None: make_settings()))
    captured: dict[str, object] = {}

    def fake_run(task_id: str, payload: dict[str, object]) -> None:
        captured.update({"task_id": task_id, **payload})

    monkeypatch.setattr(server_module, "_run_task_threaded", fake_run)
    client = TestClient(server_module.app)
    created = client.post(
        "/api/tasks",
        json={"target": str(tmp_path), "mode": "standard", "enable_native_build": True},
    ).json()
    response = client.post(f"/api/tasks/{created['task_id']}/start")

    assert response.status_code == 200
    assert store.get_task(created["task_id"])["enable_native_build"] is True
    assert captured["enable_native_build"] is True


def test_phase6_pipeline_writes_debug_from_report_payload(tmp_path: Path):
    report = AuditReport(
        input_source=InputSource(original=str(tmp_path), kind="local", local_path=str(tmp_path)),
        target=str(tmp_path),
        created_at="2026-01-01T00:00:00+00:00",
        profile=ProjectProfile(root=str(tmp_path)),
        semantic_index=SemanticIndex(),
        tool_results=[],
        dangerous_functions=[],
        program_slices=[],
        candidates=[],
        findings=[],
        verification_results=[],
        mining_debug={"candidate_validity_breakdown": {"total": 7}},
    )

    class FakeOrchestrator:
        def run(self, *_args, **kwargs):
            assert kwargs["enable_native_build"] is True
            return report

    pipeline = object.__new__(AuditPipeline)
    pipeline.orchestrator = FakeOrchestrator()
    pipeline.report_writer = ReportWriter()
    artifacts = pipeline.run(tmp_path, tmp_path / "report", enable_native_build=True)

    assert artifacts.debug_path.exists()
    assert json.loads(artifacts.debug_path.read_text(encoding="utf-8")) == report.mining_debug
