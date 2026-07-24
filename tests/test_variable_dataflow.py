from pathlib import Path

from agentic_code_audit.agents.mining import SliceAnalyzer
from agentic_code_audit.dataflow import VariableFlowAnalyzer
from agentic_code_audit.models import DangerousFunction, SemanticIndex


def _analyze(path: Path, sink_line: int, sink: str):
    lines = path.read_text(encoding="utf-8").splitlines()
    return VariableFlowAnalyzer().analyze(
        path,
        lines,
        start=1,
        end=len(lines),
        sink_line=sink_line,
        sink=sink,
    )


def test_python_ast_tracks_request_value_through_assignments_to_sink(tmp_path: Path) -> None:
    path = tmp_path / "app.py"
    path.write_text(
        "def run():\n"
        "    raw = request.args.get('cmd')\n"
        "    command = raw.strip()\n"
        "    os.system(command)\n",
        encoding="utf-8",
    )

    result = _analyze(path, 4, "os.system")

    assert result.status == "propagated"
    assert result.source == "request.args.get"
    assert [step.operation for step in result.steps] == ["source", "assign", "sink"]
    assert result.sink_variables == ["command"]


def test_python_ast_marks_direct_parameter_to_sink_separately(tmp_path: Path) -> None:
    path = tmp_path / "app.py"
    path.write_text("def run(command):\n    os.system(command)\n", encoding="utf-8")

    result = _analyze(path, 2, "os.system")

    assert result.status == "parameter_flow"
    assert result.source == "parameter:command"


def test_python_ast_does_not_link_sanitized_value_to_sink(tmp_path: Path) -> None:
    path = tmp_path / "app.py"
    path.write_text(
        "def run():\n"
        "    raw = request.args.get('cmd')\n"
        "    command = shlex.quote(raw)\n"
        "    os.system(command)\n",
        encoding="utf-8",
    )

    result = _analyze(path, 4, "os.system")

    assert result.status == "sink_unlinked"
    assert result.gaps == ["sanitized_before_sink"]


def test_cpp_lexical_flow_tracks_read_buffer_into_memcpy(tmp_path: Path) -> None:
    path = tmp_path / "parser.c"
    path.write_text(
        "void parse(int fd, char *dst) {\n"
        "  char input[64];\n"
        "  read(fd, input, sizeof(input));\n"
        "  memcpy(dst, input, 128);\n"
        "}\n",
        encoding="utf-8",
    )

    result = _analyze(path, 4, "memcpy")

    assert result.status == "propagated"
    assert "input" in result.sink_variables
    assert result.steps[-1].operation == "sink"


def test_cpp_function_signature_read_is_not_external_source(tmp_path: Path) -> None:
    path = tmp_path / "basicio.cpp"
    path.write_text(
        "size_t RemoteIo::read(byte* buf, size_t rcount) {\n"
        "  size_t totalRead = 0;\n"
        "  auto data = p_->blocksMap_[0].getData();\n"
        "  std::memcpy(&buf[totalRead], &data[0], rcount);\n"
        "  return totalRead;\n"
        "}\n",
        encoding="utf-8",
    )

    result = _analyze(path, 4, "std::memcpy")

    assert result.status == "parameter_flow"
    assert result.source == "parameter:buf"
    assert all(step.expression != "read(byte* buf" for step in result.steps)


def test_slice_analyzer_does_not_promote_context_source_without_flow(tmp_path: Path) -> None:
    path = tmp_path / "app.py"
    path.write_text(
        "def run():\n"
        "    raw = request.args.get('cmd')\n"
        "    command = 'echo safe'\n"
        "    os.system(command)\n",
        encoding="utf-8",
    )
    anchor = DangerousFunction(
        id="a1",
        file_path="app.py",
        line_start=4,
        function_name="run",
        dangerous_api="os.system",
        category="command",
        snippet="os.system(command)",
        language="python",
        sink="os.system",
        signal_kind="code_sink",
    )

    slices = SliceAnalyzer().analyze(tmp_path, [anchor], SemanticIndex(), llm_client=None)

    assert len(slices) == 1
    assert slices[0].source == ""
    assert slices[0].flow_status == "sink_unlinked"
    assert "source_sink_variable_not_linked" in slices[0].flow_gaps
