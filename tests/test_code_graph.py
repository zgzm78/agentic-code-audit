from __future__ import annotations

import subprocess
from pathlib import Path

from agentic_code_audit.agents.mining import CandidateGenerator, DangerousFunctionLocator, SliceAnalyzer
from agentic_code_audit.agents.semantic import SemanticAgent
from agentic_code_audit.code_graph import CppFunctionIndexer
from agentic_code_audit.codeql import CodeQLAnalyzer
from agentic_code_audit.config import Settings
from agentic_code_audit.models import DangerousFunction, ProgramSlice, ProjectProfile, SemanticIndex


class FakeLLM:
    enabled = False

    def chat(self, *_args, **_kwargs):
        return type("Resp", (), {"ok": False, "content": "", "error": ""})()


CPP_REMOTE_IO = """
int RemoteIo::putb(byte /*unused data*/) {
  return 0;
}

DataBuf RemoteIo::read(size_t rcount) {
  DataBuf buf(rcount);
  size_t readCount = read(buf.data(), buf.size());
  return buf;
}

size_t RemoteIo::read(byte* buf, size_t rcount) {
  if (p_->eof_)
    return 0;

  auto allow = std::min<size_t>(rcount, (p_->size_ - p_->idx_));
  size_t lowBlock = p_->idx_ / p_->blockSize_;
  p_->populateBlocks(lowBlock, lowBlock);
  size_t startPos = p_->idx_ - (lowBlock * p_->blockSize_);
  size_t totalRead = 0;
  auto data = p_->blocksMap_[lowBlock].getData();
  auto blockR = std::min<size_t>(allow, p_->blockSize_ - startPos);
  std::memcpy(&buf[totalRead], &data[startPos], blockR);
  return totalRead;
}
""".strip()


def test_cpp_function_indexer_does_not_bleed_adjacent_methods(tmp_path: Path) -> None:
    path = tmp_path / "basicio.cpp"
    path.write_text(CPP_REMOTE_IO, encoding="utf-8")

    indexer = CppFunctionIndexer()
    boundaries = indexer.boundaries_for_file(path, "src/basicio.cpp")
    sink_boundary = indexer.boundary_at(path, 22, "src/basicio.cpp")

    assert [item.name for item in boundaries] == ["RemoteIo::putb", "RemoteIo::read", "RemoteIo::read"]
    assert sink_boundary is not None
    assert sink_boundary.name == "RemoteIo::read"
    assert sink_boundary.line_start == 11
    assert sink_boundary.line_end == 24


def test_cpp_backward_slice_extracts_sink_roles_and_missing_field_guard(tmp_path: Path) -> None:
    path = tmp_path / "basicio.cpp"
    path.write_text(CPP_REMOTE_IO, encoding="utf-8")
    lines = path.read_text(encoding="utf-8").splitlines()
    indexer = CppFunctionIndexer()
    boundary = indexer.boundary_at(path, 22, "src/basicio.cpp")
    assert boundary is not None

    backward = indexer.backward_slice(boundary, lines, sink_line=22, sink="std::memcpy")

    assert backward.role_args["length"] == "blockR"
    assert any(item["symbol"] == "blockR" for item in backward.dependencies)
    assert any("p_->blockSize_" in item for item in backward.field_reads)
    assert "actual source buffer size check" in backward.missing_guards


def test_mining_uses_precise_cpp_boundary_for_adjacent_methods(tmp_path: Path) -> None:
    target = tmp_path / "project"
    target.mkdir()
    (target / "basicio.cpp").write_text("#include <cstring>\n" + CPP_REMOTE_IO, encoding="utf-8")

    dangerous = DangerousFunctionLocator().locate(target, [])
    memcpy_anchor = next(item for item in dangerous if item.line_start == 23 and "memcpy" in item.dangerous_api)
    slices = SliceAnalyzer().analyze(target, [memcpy_anchor], SemanticIndex(), FakeLLM())  # type: ignore[arg-type]

    assert memcpy_anchor.function_name == "RemoteIo::read"
    assert slices
    assert slices[0].function_name == "RemoteIo::read"
    assert slices[0].function_summary["name"] == "RemoteIo::read"
    assert "actual source buffer size check" in slices[0].backward_slice["missing_guards"]


def test_semantic_agent_extracts_cpp_function_summaries_and_call_edges(tmp_path: Path) -> None:
    target = tmp_path / "project"
    target.mkdir()
    (target / "basicio.cpp").write_text("#include <cstring>\n" + CPP_REMOTE_IO, encoding="utf-8")

    index, event = SemanticAgent(Settings.load()).run(target)

    assert event.status == "completed"
    assert any(item.name == "RemoteIo::read" and item.line_end for item in index.functions)
    assert any(edge.callee == "std::memcpy" for edge in index.call_edges)


def test_parameter_flow_without_entry_is_not_valid_candidate() -> None:
    program_slice = ProgramSlice(
        id="slice-parameter",
        dangerous_function_id="danger-parameter",
        file_path="src/parser.cpp",
        line_start=18,
        function_name="RemoteIo::read",
        source="parameter:buf",
        sink="memcpy",
        context="std::memcpy(&buf[totalRead], &data[startPos], blockR);",
        signal_kind="code_sink",
        flow_status="parameter_flow",
        slice_status="parameter_flow_unresolved",
    )

    candidates = CandidateGenerator().generate([program_slice], FakeLLM())  # type: ignore[arg-type]

    assert candidates
    assert candidates[0].valid is False
    assert candidates[0].validity == "invalid_candidate"
    assert "caller_source_unresolved" in candidates[0].invalid_reason


def test_cpp_basicio_parameter_is_not_treated_as_external_source(tmp_path: Path) -> None:
    target = tmp_path / "project"
    target.mkdir()
    source = "\n".join(
        [
            "#include <cstring>",
            "struct BasicIo { char *data(); };",
            "void parse(BasicIo& io) {",
            "  readEntry(io);",
            "}",
            "void readEntry(BasicIo& src) {",
            "  char dst[8];",
            "  std::memcpy(dst, src.data(), 16);",
            "}",
        ]
    )
    (target / "parser.cpp").write_text(source, encoding="utf-8")
    semantic_index, _event = SemanticAgent(Settings.load()).run(target)
    anchor = DangerousFunction(
        id="danger-memcpy",
        file_path="parser.cpp",
        line_start=8,
        function_name="readEntry",
        dangerous_api="std::memcpy",
        category="memory",
        snippet="std::memcpy(dst, src.data(), 16);",
        language="C++",
        sink="std::memcpy",
        signal_kind="code_sink",
    )

    slices = SliceAnalyzer().analyze(target, [anchor], semantic_index, FakeLLM())  # type: ignore[arg-type]
    candidates = CandidateGenerator().generate(slices, FakeLLM())  # type: ignore[arg-type]

    assert slices
    assert slices[0].source == "parameter:src"
    assert slices[0].flow_status == "parameter_flow"
    assert slices[0].slice_status == "parameter_flow_unresolved"
    assert "BasicIo" not in slices[0].source
    assert candidates[0].valid is False
    assert "caller_source_unresolved" in candidates[0].invalid_reason


def test_slice_keeps_unresolved_parameter_source_label(tmp_path: Path) -> None:
    target = tmp_path / "project"
    target.mkdir()
    (target / "app.py").write_text(
        "\n".join(
            [
                "import os",
                "",
                "def run_command(cmd):",
                "    return os.system(cmd)",
            ]
        ),
        encoding="utf-8",
    )
    anchor = DangerousFunction(
        id="danger-os-system",
        file_path="app.py",
        line_start=4,
        function_name="run_command",
        dangerous_api="os.system",
        category="command",
        snippet="return os.system(cmd)",
        language="Python",
        sink="os.system",
        signal_kind="code_sink",
    )

    slices = SliceAnalyzer().analyze(target, [anchor], SemanticIndex(), FakeLLM())  # type: ignore[arg-type]

    assert slices[0].source == "parameter:cmd"
    assert slices[0].flow_status == "parameter_flow"
    assert slices[0].slice_status == "parameter_flow_unresolved"


def test_python_call_graph_links_route_to_parameter_flow(tmp_path: Path) -> None:
    target = tmp_path / "project"
    target.mkdir()
    (target / "app.py").write_text(
        "\n".join(
            [
                "from flask import request",
                "import os",
                "",
                "@app.route('/run')",
                "def handler():",
                "    return run_command(request.args['cmd'])",
                "",
                "def run_command(cmd):",
                "    return os.system(cmd)",
            ]
        ),
        encoding="utf-8",
    )

    semantic_index, _event = SemanticAgent(Settings.load()).run(target)
    assert any(edge.caller == "handler" and edge.callee == "run_command" for edge in semantic_index.call_edges)
    assert any(edge.caller == "run_command" and edge.callee == "os.system" for edge in semantic_index.call_edges)

    anchor = DangerousFunction(
        id="danger-os-system",
        file_path="app.py",
        line_start=9,
        function_name="run_command",
        dangerous_api="os.system",
        category="command",
        snippet="return os.system(cmd)",
        language="Python",
        sink="os.system",
        signal_kind="code_sink",
    )
    slices = SliceAnalyzer().analyze(target, [anchor], semantic_index, FakeLLM())  # type: ignore[arg-type]

    assert slices
    assert slices[0].call_chain == ["ANY /run", "handler", "run_command", "os.system"]
    assert slices[0].source == "request.args['cmd']"
    assert slices[0].flow_status == "propagated"
    assert slices[0].slice_status == "entry_tainted_flow"


def test_interprocedural_slice_links_cross_file_multi_hop_parameter_flow(tmp_path: Path) -> None:
    target = tmp_path / "project"
    target.mkdir()
    (target / "app.py").write_text(
        "\n".join(
            [
                "from flask import request",
                "from service import dispatch",
                "",
                "@app.route('/run')",
                "def handler():",
                "    return dispatch(request.args['cmd'])",
            ]
        ),
        encoding="utf-8",
    )
    (target / "service.py").write_text(
        "\n".join(
            [
                "from runner import run",
                "",
                "def dispatch(value):",
                "    return run(value)",
            ]
        ),
        encoding="utf-8",
    )
    (target / "runner.py").write_text(
        "\n".join(
            [
                "import os",
                "",
                "def run(cmd):",
                "    return os.system(cmd)",
            ]
        ),
        encoding="utf-8",
    )

    semantic_index, _event = SemanticAgent(Settings.load()).run(target)
    anchor = DangerousFunction(
        id="danger-os-system",
        file_path="runner.py",
        line_start=4,
        function_name="run",
        dangerous_api="os.system",
        category="command",
        snippet="return os.system(cmd)",
        language="Python",
        sink="os.system",
        signal_kind="code_sink",
    )
    slices = SliceAnalyzer().analyze(target, [anchor], semantic_index, FakeLLM())  # type: ignore[arg-type]

    assert slices
    assert slices[0].source == "request.args['cmd']"
    assert slices[0].flow_status == "propagated"
    assert slices[0].slice_status == "entry_tainted_flow"
    assert slices[0].call_chain == ["ANY /run", "handler", "dispatch", "run", "os.system"]
    assert ["handler", "dispatch", "run"] in slices[0].call_paths
    assert "interprocedural_taint" in slices[0].analysis_backends


def test_semantic_agent_extracts_javascript_call_edges(tmp_path: Path) -> None:
    target = tmp_path / "project"
    target.mkdir()
    (target / "app.js").write_text(
        "\n".join(
            [
                "function handler(req) {",
                "  return run(req.query.cmd);",
                "}",
                "function run(cmd) {",
                "  return child_process.exec(cmd);",
                "}",
            ]
        ),
        encoding="utf-8",
    )

    semantic_index, _event = SemanticAgent(Settings.load()).run(target)

    assert any(edge.caller == "handler" and edge.callee == "run" for edge in semantic_index.call_edges)
    assert any(edge.caller == "run" and edge.callee == "child_process.exec" for edge in semantic_index.call_edges)


def test_go_slice_uses_semantic_boundary_and_summary_taint(tmp_path: Path) -> None:
    target = tmp_path / "project"
    target.mkdir()
    (target / "main.go").write_text(
        "\n".join(
            [
                "package main",
                "import (\"net/http\"; \"os/exec\")",
                "",
                "func Handler(r *http.Request) {",
                "    Run(r.URL.Query().Get(\"cmd\"))",
                "}",
                "",
                "func Run(cmd string) {",
                "    exec.Command(\"sh\", \"-c\", cmd).Run()",
                "}",
            ]
        ),
        encoding="utf-8",
    )

    semantic_index, _event = SemanticAgent(Settings.load()).run(target)
    dangerous = DangerousFunctionLocator().locate(target, [])
    anchor = next(item for item in dangerous if item.file_path == "main.go" and item.line_start == 9)
    slices = SliceAnalyzer().analyze(target, [anchor], semantic_index, FakeLLM())  # type: ignore[arg-type]

    assert any(edge.caller == "Handler" and edge.callee == "Run" for edge in semantic_index.call_edges)
    assert slices
    assert slices[0].function_name == "Run"
    assert slices[0].function_summary["language"] == "Go"
    assert slices[0].source == 'r.URL.Query().Get("cmd")'
    assert slices[0].flow_status == "propagated"
    assert slices[0].call_chain[:2] == ["Handler", "Run"]
    assert slices[0].slice_status == "local_tainted_flow"


def test_codeql_parser_extracts_sarif_path_evidence(tmp_path: Path) -> None:
    target = tmp_path / "project"
    target.mkdir()
    sarif = tmp_path / "results.sarif"
    sarif.write_text(
        """
{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "CodeQL",
          "rules": [
            {
              "id": "py/command-line-injection",
              "defaultConfiguration": {"level": "error"}
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "py/command-line-injection",
          "message": {"text": "User input reaches command execution."},
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {"uri": "runner.py"},
                "region": {"startLine": 4}
              }
            }
          ],
          "codeFlows": [
            {
              "threadFlows": [
                {
                  "locations": [
                    {
                      "location": {
                        "message": {"text": "source request.args"},
                        "physicalLocation": {
                          "artifactLocation": {"uri": "app.py"},
                          "region": {"startLine": 6}
                        }
                      }
                    },
                    {
                      "location": {
                        "message": {"text": "sink os.system"},
                        "physicalLocation": {
                          "artifactLocation": {"uri": "runner.py"},
                          "region": {"startLine": 4}
                        }
                      }
                    }
                  ]
                }
              ]
            }
          ]
        }
      ]
    }
  ]
}
""".strip(),
        encoding="utf-8",
    )

    evidence = CodeQLAnalyzer(Settings.load()).parse_sarif(sarif, target)

    assert len(evidence) == 1
    assert evidence[0].rule_id == "py/command-line-injection"
    assert evidence[0].file_path == "runner.py"
    assert evidence[0].line_start == 4
    assert evidence[0].path[0]["file_path"] == "app.py"
    assert evidence[0].path[-1]["message"] == "sink os.system"


def test_codeql_analyzer_skips_when_executable_missing(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("agentic_code_audit.codeql.shutil.which", lambda _name: None)

    result, evidence = CodeQLAnalyzer(Settings.load()).run(tmp_path, ProjectProfile(root=str(tmp_path), languages={"Python": 1}))

    assert result.status == "skipped"
    assert "not installed" in result.summary
    assert evidence == []


def test_codeql_analyzer_downloads_query_pack_before_analyze(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "project"
    target.mkdir()
    (target / "app.py").write_text("print('ok')\n", encoding="utf-8")
    commands: list[list[str]] = []
    analyzer = CodeQLAnalyzer(Settings.load(), work_dir=tmp_path / "codeql-work")
    monkeypatch.setattr("agentic_code_audit.codeql.shutil.which", lambda _name: "codeql")
    monkeypatch.setattr(analyzer, "parse_sarif", lambda _sarif, _target: [])

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(analyzer, "_run_command", fake_run)

    result, evidence = analyzer.run(target, ProjectProfile(root=str(target), languages={"Python": 1}))

    assert result.status == "ok"
    assert evidence == []
    assert commands[0][:3] == ["codeql", "database", "create"]
    assert commands[1] == ["codeql", "pack", "download", "codeql/python-queries"]
    assert commands[2][:3] == ["codeql", "database", "analyze"]


def test_codeql_analyzer_finds_bundled_codeql_path(tmp_path: Path, monkeypatch) -> None:
    tools_dir = tmp_path / ".tools" / "codeql"
    tools_dir.mkdir(parents=True)
    executable = tools_dir / "codeql"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("agentic_code_audit.codeql.shutil.which", lambda _name: None)

    assert CodeQLAnalyzer(Settings.load()).available() is True
