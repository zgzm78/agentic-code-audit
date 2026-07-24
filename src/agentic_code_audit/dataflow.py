from __future__ import annotations

import ast
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class FlowStep:
    line: int
    operation: str
    variable: str
    expression: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class VariableFlowResult:
    status: str = "sink_unlinked"
    source: str = ""
    source_variables: list[str] = field(default_factory=list)
    sink_variables: list[str] = field(default_factory=list)
    steps: list[FlowStep] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)

    @property
    def linked(self) -> bool:
        return self.status in {"direct", "propagated"}


class VariableFlowAnalyzer:
    """Best-effort intra-procedural variable flow for supported source languages."""

    PYTHON_SUFFIXES = {".py"}
    LEXICAL_SUFFIXES = {
        ".js", ".jsx", ".ts", ".tsx", ".c", ".cc", ".cpp", ".cxx",
        ".h", ".hpp", ".go", ".rs",
    }
    SANITIZER_NAMES = {
        "escape", "sanitize", "realpath", "quote", "shlex.quote",
        "html.escape", "urllib.parse.quote",
    }

    def analyze(
        self,
        path: Path,
        lines: list[str],
        *,
        start: int,
        end: int,
        sink_line: int,
        sink: str,
    ) -> VariableFlowResult:
        suffix = path.suffix.lower()
        if suffix in self.PYTHON_SUFFIXES:
            return self._python(path, sink_line, sink)
        if suffix in self.LEXICAL_SUFFIXES:
            return self._lexical(lines, start=start, end=end, sink_line=sink_line, sink=sink, suffix=suffix)
        return VariableFlowResult(gaps=["language_dataflow_not_supported"])

    def _python(self, path: Path, sink_line: int, sink: str) -> VariableFlowResult:
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source)
        except (OSError, SyntaxError):
            return VariableFlowResult(gaps=["python_ast_unavailable"])

        scope: ast.AST = tree
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                end = int(getattr(node, "end_lineno", node.lineno))
                if int(node.lineno) <= sink_line <= end:
                    scope = node
                    break

        parameters: set[str] = set()
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            parameters = {
                arg.arg
                for arg in [*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs]
            }
        tainted: dict[str, list[FlowStep]] = {
            name: [FlowStep(int(getattr(scope, "lineno", 1)), "parameter", name, name)]
            for name in parameters
        }
        parameter_only = set(parameters)
        sanitized: set[str] = set()
        nodes = sorted(
            (node for node in ast.walk(scope) if hasattr(node, "lineno")),
            key=lambda item: (int(getattr(item, "lineno", 0)), int(getattr(item, "col_offset", 0))),
        )

        sink_call: ast.Call | None = None
        for node in nodes:
            line = int(getattr(node, "lineno", 0))
            if line > sink_line:
                break
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                targets, value = self._python_assignment(node)
                if value is not None:
                    self._track_python_assignment(
                        targets, value, line, source, tainted, parameter_only, sanitized
                    )
            if isinstance(node, ast.Call) and line == sink_line and self._python_matches_sink(node, sink):
                sink_call = node
                break

        if sink_call is None:
            return VariableFlowResult(gaps=["sink_call_not_resolved"])
        return self._python_sink_result(
            sink_call, source, sink_line, tainted, parameter_only, sanitized
        )

    def _track_python_assignment(
        self,
        targets: list[str],
        value: ast.AST,
        line: int,
        source_text: str,
        tainted: dict[str, list[FlowStep]],
        parameter_only: set[str],
        sanitized: set[str],
    ) -> None:
        value_text = ast.get_source_segment(source_text, value) or ast.dump(value, include_attributes=False)
        refs = self._python_names(value)
        source_expr = self._python_source(value)
        sanitizer = self._python_sanitizer(value)
        for target in targets:
            if sanitizer:
                tainted.pop(target, None)
                sanitized.add(target)
            elif source_expr:
                tainted[target] = [FlowStep(line, "source", target, source_expr)]
                parameter_only.discard(target)
            else:
                upstream = next((name for name in refs if name in tainted), "")
                if not upstream:
                    continue
                tainted[target] = [*tainted[upstream], FlowStep(line, "assign", target, value_text)]
                if upstream in parameter_only:
                    parameter_only.add(target)
                else:
                    parameter_only.discard(target)

    def _python_sink_result(
        self,
        sink_call: ast.Call,
        source: str,
        sink_line: int,
        tainted: dict[str, list[FlowStep]],
        parameter_only: set[str],
        sanitized: set[str],
    ) -> VariableFlowResult:
        sink_name = self._python_call_name(sink_call.func)
        sink_text = ast.get_source_segment(source, sink_call) or sink_name
        arg_nodes = [*sink_call.args, *[keyword.value for keyword in sink_call.keywords]]
        direct_source = next((self._python_source(arg) for arg in arg_nodes if self._python_source(arg)), "")
        sink_variables = sorted({name for arg in arg_nodes for name in self._python_names(arg)})
        if direct_source:
            return VariableFlowResult(
                status="direct",
                source=direct_source,
                sink_variables=sink_variables,
                steps=[
                    FlowStep(sink_line, "source", direct_source, direct_source),
                    FlowStep(sink_line, "sink", sink_name, sink_text),
                ],
            )
        linked = self._choose_linked_variable(sink_variables, tainted, parameter_only)
        if linked:
            status = "parameter_flow" if linked in parameter_only else "propagated"
            steps = [*tainted[linked], FlowStep(sink_line, "sink", sink_name, sink_text)]
            return VariableFlowResult(
                status=status,
                source=f"parameter:{linked}" if status == "parameter_flow" else steps[0].expression,
                source_variables=[linked],
                sink_variables=sink_variables,
                steps=steps,
            )
        gaps = ["sanitized_before_sink"] if sanitized.intersection(sink_variables) else ["source_sink_variable_not_linked"]
        return VariableFlowResult(sink_variables=sink_variables, gaps=gaps)

    def _lexical(
        self,
        lines: list[str],
        *,
        start: int,
        end: int,
        sink_line: int,
        sink: str,
        suffix: str,
    ) -> VariableFlowResult:
        tainted: dict[str, list[FlowStep]] = {}
        parameter_only: set[str] = set()
        sanitized: set[str] = set()
        first_line = lines[start - 1] if 1 <= start <= len(lines) else ""
        for name in self._function_parameters(first_line):
            tainted[name] = [FlowStep(start, "parameter", name, name)]
            parameter_only.add(name)

        sink_text = lines[sink_line - 1] if 1 <= sink_line <= len(lines) else ""
        for number in range(start, min(end, sink_line) + 1):
            text = lines[number - 1]
            writer = self._source_writer(text)
            if writer:
                variable, expression = writer
                tainted[variable] = [FlowStep(number, "source", variable, expression)]
                parameter_only.discard(variable)
            assignment = re.search(
                r"(?:\b(?:const|let|var|auto|char|int|long|size_t|ssize_t|string|std::string)\s+)?"
                r"([A-Za-z_$][\w$]*)\s*=\s*(.+?);?\s*$",
                text,
            )
            if assignment:
                self._track_lexical_assignment(
                    assignment.group(1), assignment.group(2), number,
                    tainted, parameter_only, sanitized,
                )

        args = self._call_args(sink_text, sink)
        sink_variables = sorted(self._identifiers(args))
        direct_source = self._text_source(args)
        if direct_source:
            return VariableFlowResult(
                status="direct",
                source=direct_source,
                sink_variables=sink_variables,
                steps=[
                    FlowStep(sink_line, "source", direct_source, args.strip()),
                    FlowStep(sink_line, "sink", sink, sink_text.strip()),
                ],
            )
        linked = self._choose_linked_variable(sink_variables, tainted, parameter_only)
        if linked:
            status = "parameter_flow" if linked in parameter_only else "propagated"
            steps = [*tainted[linked], FlowStep(sink_line, "sink", sink, sink_text.strip())]
            return VariableFlowResult(
                status=status,
                source=f"parameter:{linked}" if status == "parameter_flow" else steps[0].expression,
                source_variables=[linked],
                sink_variables=sink_variables,
                steps=steps,
            )
        gaps = ["sanitized_before_sink"] if sanitized.intersection(sink_variables) else ["source_sink_variable_not_linked"]
        if suffix in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"} and not sink_variables:
            gaps.append("sink_arguments_not_resolved")
        return VariableFlowResult(sink_variables=sink_variables, gaps=gaps)

    def _track_lexical_assignment(
        self,
        variable: str,
        expression: str,
        line: int,
        tainted: dict[str, list[FlowStep]],
        parameter_only: set[str],
        sanitized: set[str],
    ) -> None:
        refs = self._identifiers(expression)
        if self._text_has_sanitizer(expression):
            tainted.pop(variable, None)
            sanitized.add(variable)
            return
        direct_source = self._text_source(expression)
        if direct_source:
            tainted[variable] = [FlowStep(line, "source", variable, expression.strip())]
            parameter_only.discard(variable)
            return
        upstream = next((name for name in refs if name in tainted), "")
        if not upstream:
            return
        tainted[variable] = [*tainted[upstream], FlowStep(line, "assign", variable, expression.strip())]
        if upstream in parameter_only:
            parameter_only.add(variable)
        else:
            parameter_only.discard(variable)

    def _python_assignment(self, node: ast.AST) -> tuple[list[str], ast.AST | None]:
        if isinstance(node, ast.Assign):
            return [name for target in node.targets for name in self._python_target_names(target)], node.value
        if isinstance(node, ast.AnnAssign):
            return self._python_target_names(node.target), node.value
        if isinstance(node, ast.NamedExpr):
            return self._python_target_names(node.target), node.value
        return [], None

    def _python_target_names(self, node: ast.AST) -> list[str]:
        if isinstance(node, ast.Name):
            return [node.id]
        if isinstance(node, (ast.Tuple, ast.List)):
            return [name for item in node.elts for name in self._python_target_names(item)]
        return []

    def _python_names(self, node: ast.AST) -> set[str]:
        return {item.id for item in ast.walk(node) if isinstance(item, ast.Name)}

    def _python_source(self, node: ast.AST) -> str:
        if isinstance(node, ast.Call):
            name = self._python_call_name(node.func)
            if name in {"input", "os.getenv", "getenv"} or name.startswith(("request.", "req.")):
                return name
        if isinstance(node, (ast.Attribute, ast.Subscript)) and self._python_root_name(node) in {"request", "req"}:
            return self._python_root_name(node)
        for child in ast.iter_child_nodes(node):
            found = self._python_source(child)
            if found:
                return found
        return ""

    def _python_sanitizer(self, node: ast.AST) -> bool:
        return isinstance(node, ast.Call) and self._python_call_name(node.func).lower() in self.SANITIZER_NAMES

    def _python_root_name(self, node: ast.AST) -> str:
        current = node
        while isinstance(current, (ast.Attribute, ast.Subscript)):
            current = current.value
        return current.id if isinstance(current, ast.Name) else ""

    def _python_call_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            prefix = self._python_call_name(node.value)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        return ""

    def _python_matches_sink(self, node: ast.Call, sink: str) -> bool:
        call = self._python_call_name(node.func).lower()
        expected = sink.lower().replace("std::", "")
        return call == expected or call.endswith(f".{expected}") or expected.endswith(f".{call}")

    def _function_parameters(self, line: str) -> list[str]:
        match = re.search(r"\(([^()]*)\)", line)
        if not match:
            return []
        output: list[str] = []
        type_words = {"string", "int", "int64", "uint64", "bool", "error", "byte", "rune", "float64", "Request"}
        for item in match.group(1).split(","):
            names = re.findall(r"[A-Za-z_$][\w$]*", item.split("=")[0])
            if names:
                if len(names) > 1 and (names[-1] in type_words or names[-1][:1].isupper()):
                    output.append(names[0])
                else:
                    output.append(names[-1])
        return output

    def _source_writer(self, text: str) -> tuple[str, str] | None:
        if self._looks_like_function_signature(text):
            return None
        match = re.search(r"\b(read|recv)\s*\([^,]+,\s*([A-Za-z_]\w*)", text)
        if match:
            return match.group(2), match.group(0)
        match = re.search(r"\bfread\s*\(\s*([A-Za-z_]\w*)", text)
        if match:
            return match.group(1), match.group(0)
        return None

    def _looks_like_function_signature(self, text: str) -> bool:
        stripped = text.strip()
        if stripped.endswith(";"):
            return False
        if not re.search(r"\)\s*(?:const\s*)?(?:noexcept\s*)?(?:\{|$)", stripped):
            return False
        return bool(
            re.match(
                r"(?:template\s*<[^>]+>\s*)?"
                r"(?:(?:static|inline|virtual|constexpr|friend|extern)\s+)*"
                r"[\w:<>\*&\s]+\s+[A-Za-z_~][A-Za-z0-9_:~]*\s*\([^;{}]*\)",
                stripped,
            )
        )

    def _text_source(self, text: str) -> str:
        patterns = (
            r"request\.(?:args|form|json|values)", r"req\.(?:query|body|params)",
            r"\$_(?:GET|POST|REQUEST)", r"\bargv\b", r"\b(?:input|getenv)\s*\(",
        )
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return match.group(0)
        return ""

    def _text_has_sanitizer(self, text: str) -> bool:
        lowered = text.lower()
        return any(f"{name}(" in lowered for name in self.SANITIZER_NAMES)

    def _call_args(self, text: str, sink: str) -> str:
        names = [re.escape(sink), re.escape(sink.replace("std::", ""))]
        match = re.search(rf"(?:{'|'.join(names)})\s*\((.*)\)", text)
        return match.group(1) if match else text

    def _identifiers(self, text: str) -> set[str]:
        return set(re.findall(r"\b[A-Za-z_$][\w$]*\b", text))

    def _choose_linked_variable(
        self,
        sink_variables: list[str],
        tainted: dict[str, list[FlowStep]],
        parameter_only: set[str],
    ) -> str:
        non_parameter = next(
            (name for name in sink_variables if name in tainted and name not in parameter_only),
            "",
        )
        if non_parameter:
            return non_parameter
        return next((name for name in sink_variables if name in tainted), "")
