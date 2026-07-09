import sqlite3
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from agentic_code_audit.agents.mining import (
    CandidateGenerator,
    ClueAggregator,
    DangerousFunctionLocator,
    SliceAnalyzer,
    VulnerabilityClassifier,
)
from agentic_code_audit.agents.profiler import ProjectProfiler
from agentic_code_audit.agents.recon import ReconAgent
from agentic_code_audit.agents.verification import (
    BuildManager,
    CheckerOutcome,
    CommandInjectionChecker,
    DependencyChecker,
    EnvironmentManager,
    EvidenceChecker,
    ExploitAgent,
    HarnessPlan,
    MemorySafetyChecker,
    PathTraversalChecker,
    PocAnalysis,
    PocPlan,
    RuntimeManager,
    SandboxExecutor,
    SQLInjectionChecker,
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
    ToolDefinition,
    ToolInvocation,
    ToolParsers,
    ToolPlanner,
    ToolRegistry,
    ToolRunner,
)


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
    assert findings[0].severity == "critical"
    assert findings[0].should_verify is True
    assert findings[0].tool_run_refs == ["run-1", "run-2"]
    assert findings[0].artifact_refs == ["artifact-1"]


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
    assert "# 智能体源码安全审计报告" in markdown
    assert "## 任务摘要" in markdown
    assert "## Artifact 索引" in markdown
    assert "candidate_id: `candidate-1`" in markdown
    assert "runtime_type" not in markdown.lower() or "运行类型" in markdown
    assert "evidence_artifact_ids: `evidence-1`" in markdown
    assert "鏅鸿兘" not in markdown


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
    import agentic_code_audit.agents.verification as verification_module

    monkeypatch.setattr(verification_module.shutil, "which", lambda _name: None)
    (tmp_path / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.20)\n", encoding="utf-8")
    finding = _phase5_finding("unsafe_memory_copy", "main.cpp")
    profile = ProjectProfile(root=str(tmp_path), languages={"C++": 1})
    env = EnvironmentManager().inspect(tmp_path, profile, finding)

    decision, executable = BuildManager().prepare(tmp_path, profile, finding, env, tmp_path / "out")
    assert executable is None
    assert decision.status == "blocked"
    assert decision.missing_tools
    assert decision.install_hints


def test_phase5_sandbox_executor_records_local_fallback_artifacts(tmp_path: Path, monkeypatch):
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
    assert outcome.local_fallback is True
    assert outcome.status in {"verified", "partially_verified"}
    assert (tmp_path / "sandbox" / "command.json").exists()
    assert (tmp_path / "sandbox" / "stdout.log").exists()
    assert any(path.name == "changed_files.json" for path in outcome.artifact_paths)


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
    assert result.local_fallback is True

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
