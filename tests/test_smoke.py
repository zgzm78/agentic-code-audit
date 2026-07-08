from pathlib import Path

from agentic_code_audit.agents.mining import DangerousFunctionLocator, SliceAnalyzer
from agentic_code_audit.agents.verification import EvidenceChecker, PocAnalysis, PocPlan, VerificationAgent
from agentic_code_audit.cli import main as cli_main
from agentic_code_audit.inputs import TargetResolver
from agentic_code_audit.models import Finding, ProjectProfile, SemanticIndex


class FakeLLM:
    enabled = True

    def chat(self, *_args, **_kwargs):
        return type("Resp", (), {"ok": True, "content": "测试 LLM 输出", "error": ""})()


def test_cli_rejects_missing_deepseek_key(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "")
    code = cli_main(["audit", "examples/vulnerable-python", "--project-dir", str(tmp_path)])
    assert code == 2


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
