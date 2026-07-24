from __future__ import annotations

import ast
import re
from collections import defaultdict
from pathlib import Path

from ..code_graph import CPP_SUFFIXES, CppFunctionIndexer, extract_call_args, split_call_args
from ..config import Settings
from ..models import AgentEvent, CallEdgeSummary, FunctionSummary, RouteSummary, SemanticIndex, normalize_path, utc_now
from ..path_policy import PathPolicy


PY_FUNCTION = re.compile(r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*:")
JS_FUNCTION = re.compile(r"^\s*(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)")
GO_FUNCTION = re.compile(r"^\s*func\s+(?:\([^)]+\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)")
JAVA_METHOD = re.compile(
    r"^\s*(?:(?:public|private|protected|static|final|synchronized|native|abstract)\s+)*"
    r"[\w<>\[\], ?]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*(?:throws\s+[^{]+)?\{?"
)
PHP_FUNCTION = re.compile(r"^\s*(?:(?:public|private|protected|static)\s+)*function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)")
PY_ROUTE = re.compile(r"@\w+\.route\(\s*['\"]([^'\"]+)['\"]")
EXPRESS_ROUTE = re.compile(r"\b(app|router)\.(get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]")

SOURCE_MARKERS = (
    "request.", "request[", "req.", "req[", "input(", "$_GET", "$_POST",
    "params", "query", "URL.Query", "FormValue", "getParameter",
)
SINK_MARKERS = (
    "execute(",
    "query(",
    "os.system",
    "os.popen",
    "subprocess.",
    "shell_exec",
    "system(",
    "open(",
    "readfile",
    "send_file",
    "child_process.",
    "Runtime.getRuntime().exec",
    "ProcessBuilder",
    "exec.Command",
    "mysqli_query",
    "pg_query",
)
GENERIC_SUFFIXES = {".go": "Go", ".java": "Java", ".php": "PHP"}


class SemanticAgent:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.path_policy = PathPolicy()
        self.cpp_indexer = CppFunctionIndexer()

    def run(self, target: Path) -> tuple[SemanticIndex, AgentEvent]:
        event = AgentEvent(agent="SemanticAgent", action="build_semantic_index", status="running")
        index = SemanticIndex()
        module_tags: dict[str, set[str]] = defaultdict(set)

        scanned = 0
        for path in target.rglob("*"):
            if scanned >= self.settings.max_files:
                break
            if not path.is_file():
                continue
            rel = normalize_path(path, target)
            if not self.path_policy.include_source(rel):
                continue
            try:
                if path.stat().st_size > self.settings.max_file_size:
                    continue
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            scanned += 1
            self._extract_python(rel, text, index)
            self._extract_js(rel, text, index)
            self._extract_cpp(rel, path, text, index)
            self._extract_generic(rel, path, text, index)
            self._extract_symbols(text, index, module_tags[rel])

        index.source_symbols = sorted(set(index.source_symbols))
        index.sink_symbols = sorted(set(index.sink_symbols))
        index.module_summaries = {
            path: f"tags={', '.join(sorted(tags))}" for path, tags in sorted(module_tags.items()) if tags
        }
        event.status = "completed"
        event.detail = (
            f"functions={len(index.functions)}; routes={len(index.routes)}; "
            f"call_edges={len(index.call_edges)}; "
            f"sources={len(index.source_symbols)}; sinks={len(index.sink_symbols)}"
        )
        event.finished_at = utc_now()
        return index, event

    def _extract_python(self, rel: str, text: str, index: SemanticIndex) -> None:
        try:
            tree = ast.parse(text)
        except SyntaxError:
            self._extract_python_regex(rel, text, index)
            return
        lines = text.splitlines()
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            args = ", ".join(self._python_parameters(node.args))
            line_end = int(getattr(node, "end_lineno", node.lineno))
            body_text = "\n".join(lines[node.lineno - 1 : line_end])
            tags = self._text_tags(body_text)
            calls = self._python_function_calls(node, text)
            if calls:
                tags.append("calls")
            index.functions.append(
                FunctionSummary(
                    name=node.name,
                    file_path=rel,
                    line_start=int(node.lineno),
                    line_end=line_end,
                    signature=f"def {node.name}({args})",
                    summary=self._summarize_function_name(node.name, args),
                    tags=list(dict.fromkeys(tags)),
                    language="Python",
                    parameters=self._python_parameters(node.args),
                    calls=sorted({callee for callee, _line, _arguments in calls}),
                    sinks=[marker for marker in SINK_MARKERS if marker in body_text],
                    sources=[marker for marker in SOURCE_MARKERS if marker in body_text],
                )
            )
            for callee, line_no, arguments in calls[:80]:
                index.call_edges.append(
                    CallEdgeSummary(
                        caller=node.name,
                        callee=callee,
                        file_path=rel,
                        line=line_no,
                        resolution="ast",
                        confidence=0.8,
                        arguments=arguments,
                    )
                )
            for route in self._python_routes_for(node):
                index.routes.append(
                    RouteSummary(
                        method=route[0],
                        route=route[1],
                        handler=node.name,
                        file_path=rel,
                        line_start=route[2],
                    )
                )

    def _extract_python_regex(self, rel: str, text: str, index: SemanticIndex) -> None:
        pending_route: tuple[str, int] | None = None
        for line_no, line in enumerate(text.splitlines(), start=1):
            route = PY_ROUTE.search(line)
            if route:
                pending_route = (route.group(1), line_no)
                continue
            function = PY_FUNCTION.search(line)
            if function:
                name = function.group(1)
                args = function.group(2)
                tags = self._line_tags(line)
                index.functions.append(
                    FunctionSummary(
                        name=name,
                        file_path=rel,
                        line_start=line_no,
                        signature=f"def {name}({args})",
                        summary=self._summarize_function_name(name, args),
                        tags=tags,
                        language="Python",
                        parameters=[item.strip().split("=")[0].strip() for item in args.split(",") if item.strip()],
                    )
                )
                if pending_route:
                    index.routes.append(
                        RouteSummary(
                            method="ANY",
                            route=pending_route[0],
                            handler=name,
                            file_path=rel,
                            line_start=pending_route[1],
                        )
                    )
                    pending_route = None

    def _extract_js(self, rel: str, text: str, index: SemanticIndex) -> None:
        lines = text.splitlines()
        functions: list[tuple[str, str, int, str]] = []
        for line_no, line in enumerate(lines, start=1):
            route = EXPRESS_ROUTE.search(line)
            if route:
                handler_match = re.search(r"[,]\s*([A-Za-z_$][\w$]*)\s*[,)]", line[route.end() :])
                index.routes.append(
                    RouteSummary(
                        method=route.group(2).upper(),
                        route=route.group(3),
                        handler=handler_match.group(1) if handler_match else "<inline>",
                        file_path=rel,
                        line_start=line_no,
                    )
                )
            function = JS_FUNCTION.search(line)
            if function:
                name = function.group(1)
                args = function.group(2)
                functions.append((name, args, line_no, line))
        for index_no, (name, args, line_no, line) in enumerate(functions):
            next_line = functions[index_no + 1][2] if index_no + 1 < len(functions) else len(lines) + 1
            line_end = max(line_no, next_line - 1)
            body = "\n".join(lines[line_no - 1 : line_end])
            tags = self._text_tags(body)
            calls = self._js_call_names(lines[line_no:line_end])
            index.functions.append(
                FunctionSummary(
                    name=name,
                    file_path=rel,
                    line_start=line_no,
                    line_end=line_end,
                    signature=f"function {name}({args})",
                    summary=self._summarize_function_name(name, args),
                    tags=list(dict.fromkeys([*tags, *self._line_tags(line)])),
                    language="JavaScript",
                    parameters=[item.strip().split("=")[0].strip() for item in args.split(",") if item.strip()],
                    calls=sorted({callee for callee, _line, _arguments in calls}),
                )
            )
            for callee, call_line, arguments in calls[:80]:
                index.call_edges.append(
                    CallEdgeSummary(
                        caller=name,
                        callee=callee,
                        file_path=rel,
                        line=line_no + call_line,
                        resolution="lexical",
                        confidence=0.62,
                        arguments=arguments,
                    )
                )

    def _extract_cpp(self, rel: str, path: Path, text: str, index: SemanticIndex) -> None:
        if path.suffix.lower() not in CPP_SUFFIXES:
            return
        lines = text.splitlines()
        for boundary in self.cpp_indexer.boundaries_from_text(text, rel, "C" if path.suffix.lower() == ".c" else "C++"):
            summary = self.cpp_indexer.summarize(boundary, lines)
            tags = ["native"]
            if summary.sinks:
                tags.append("sink")
            if summary.sources:
                tags.append("source")
            index.functions.append(
                FunctionSummary(
                    name=summary.name,
                    file_path=rel,
                    line_start=summary.line_start,
                    line_end=summary.line_end,
                    signature=summary.signature,
                    summary=self._summarize_function_name(summary.name, ", ".join(summary.parameters)),
                    tags=tags,
                    language=summary.language,
                    parameters=summary.parameters,
                    calls=summary.calls,
                    field_reads=summary.field_reads,
                    field_writes=summary.field_writes,
                    guards=summary.guards,
                    sinks=summary.sinks,
                    sources=summary.sources,
                )
            )
            index.call_edges.extend(
                CallEdgeSummary(
                    caller=edge.caller,
                    callee=edge.callee,
                    file_path=edge.file_path,
                    line=edge.line,
                    resolution=edge.resolution,
                    confidence=edge.confidence,
                    arguments=list(edge.arguments),
                )
                for edge in summary.call_edges
            )

    def _extract_generic(self, rel: str, path: Path, text: str, index: SemanticIndex) -> None:
        language = GENERIC_SUFFIXES.get(path.suffix.lower())
        if not language:
            return
        matcher = {
            "Go": GO_FUNCTION,
            "Java": JAVA_METHOD,
            "PHP": PHP_FUNCTION,
        }[language]
        lines = text.splitlines()
        for line_no, line in enumerate(lines, start=1):
            match = matcher.search(line)
            if not match:
                continue
            name = match.group(1)
            args = match.group(2)
            line_end = self._brace_end(lines, line_no)
            body = "\n".join(lines[line_no - 1 : line_end])
            calls = self._generic_call_names(lines[line_no - 1 : line_end], line_no)
            index.functions.append(
                FunctionSummary(
                    name=name,
                    file_path=rel,
                    line_start=line_no,
                    line_end=line_end,
                    signature=line.strip(),
                    summary=self._summarize_function_name(name, args),
                    tags=list(dict.fromkeys([*self._text_tags(body), "calls"] if calls else self._text_tags(body))),
                    language=language,
                    parameters=self._generic_parameters(args, language),
                    calls=sorted({callee for callee, _line, _args in calls}),
                    sinks=[marker for marker in SINK_MARKERS if marker in body],
                    sources=[marker for marker in SOURCE_MARKERS if marker in body],
                )
            )
            for callee, call_line, arguments in calls[:80]:
                if callee == name:
                    continue
                index.call_edges.append(
                    CallEdgeSummary(
                        caller=name,
                        callee=callee,
                        file_path=rel,
                        line=call_line,
                        resolution="lexical",
                        confidence=0.58,
                        arguments=arguments,
                    )
                )

    def _extract_symbols(self, text: str, index: SemanticIndex, tags: set[str]) -> None:
        for marker in SOURCE_MARKERS:
            if marker in text:
                index.source_symbols.append(marker)
                tags.add("source")
        for marker in SINK_MARKERS:
            if marker in text:
                index.sink_symbols.append(marker)
                tags.add("sink")
        lowered = text.lower()
        for tag, markers in {
            "auth": ("login", "password", "token", "jwt"),
            "file": ("upload", "download", "open(", "readfile"),
            "database": ("select ", "insert ", "update ", "delete ", "execute(", "query("),
            "command": ("os.system", "os.popen", "subprocess", "shell_exec", "child_process"),
        }.items():
            if any(marker in lowered for marker in markers):
                tags.add(tag)

    def _line_tags(self, line: str) -> list[str]:
        tags = []
        if any(marker in line for marker in SOURCE_MARKERS):
            tags.append("source")
        if any(marker in line for marker in SINK_MARKERS):
            tags.append("sink")
        return tags

    def _text_tags(self, text: str) -> list[str]:
        tags = []
        if any(marker in text for marker in SOURCE_MARKERS):
            tags.append("source")
        if any(marker in text for marker in SINK_MARKERS):
            tags.append("sink")
        return tags

    def _python_parameters(self, args: ast.arguments) -> list[str]:
        return [
            item.arg
            for item in [*args.posonlyargs, *args.args, *args.kwonlyargs]
            if item.arg
        ]

    def _python_function_calls(self, node: ast.FunctionDef | ast.AsyncFunctionDef, source_text: str = "") -> list[tuple[str, int, list[str]]]:
        calls: list[tuple[str, int, list[str]]] = []
        for stmt in node.body:
            for child in ast.walk(stmt):
                if isinstance(child, ast.Call):
                    name = self._python_call_name(child.func)
                    if name:
                        arguments = [
                            ast.get_source_segment(source_text, item) or ast.dump(item, include_attributes=False)
                            for item in [*child.args, *[keyword.value for keyword in child.keywords]]
                        ]
                        calls.append((name, int(getattr(child, "lineno", node.lineno)), arguments))
        return calls

    def _python_call_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._python_call_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        return ""

    def _python_routes_for(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[tuple[str, str, int]]:
        routes: list[tuple[str, str, int]] = []
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            name = self._python_call_name(decorator.func)
            if not name.endswith(".route") or not decorator.args:
                continue
            route_node = decorator.args[0]
            route = route_node.value if isinstance(route_node, ast.Constant) and isinstance(route_node.value, str) else ""
            if not route:
                continue
            method = "ANY"
            for keyword in decorator.keywords:
                if keyword.arg == "methods" and isinstance(keyword.value, (ast.List, ast.Tuple)):
                    values = [
                        str(item.value).upper()
                        for item in keyword.value.elts
                        if isinstance(item, ast.Constant) and isinstance(item.value, str)
                    ]
                    if values:
                        method = "/".join(values)
            routes.append((method, route, int(getattr(decorator, "lineno", node.lineno))))
        return routes

    def _js_call_names(self, lines: list[str]) -> list[tuple[str, int, list[str]]]:
        keywords = {"if", "for", "while", "switch", "return", "function", "catch", "new", "typeof", "sizeof"}
        calls: list[tuple[str, int, list[str]]] = []
        for offset, line in enumerate(lines, start=1):
            for match in re.finditer(r"\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)\s*\(", line):
                name = match.group(1)
                if name.split(".")[-1] in keywords:
                    continue
                calls.append((name, offset, split_call_args(extract_call_args(line[match.start() :], name))))
        return calls

    def _generic_call_names(self, lines: list[str], first_line: int) -> list[tuple[str, int, list[str]]]:
        keywords = {
            "if", "for", "while", "switch", "return", "catch", "new", "func", "function",
            "class", "public", "private", "protected", "static", "echo",
        }
        calls: list[tuple[str, int, list[str]]] = []
        for offset, line in enumerate(lines, start=0):
            for match in re.finditer(r"\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(", line):
                name = match.group(1).lstrip("$")
                if name.split(".")[-1] in keywords:
                    continue
                calls.append((name, first_line + offset, split_call_args(extract_call_args(line[match.start() :], name))))
        return calls

    def _generic_parameters(self, args: str, language: str) -> list[str]:
        params: list[str] = []
        for raw in args.split(","):
            item = raw.strip()
            if not item:
                continue
            item = item.split("=", 1)[0].strip()
            if language == "PHP":
                match = re.search(r"\$([A-Za-z_][A-Za-z0-9_]*)", item)
                if match:
                    params.append(match.group(1))
                continue
            if language == "Go":
                names = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", item)
                if names:
                    params.append(names[0])
                continue
            token = item.split()[-1].strip("*&[]") if item.split() else ""
            if token:
                params.append(token)
        return params

    def _brace_end(self, lines: list[str], line_no: int) -> int:
        depth = 0
        opened = False
        for index in range(line_no - 1, len(lines)):
            line = lines[index]
            depth += line.count("{")
            if "{" in line:
                opened = True
            depth -= line.count("}")
            if opened and depth <= 0:
                return index + 1
        next_function = next(
            (
                index + 1
                for index in range(line_no, len(lines))
                if GO_FUNCTION.search(lines[index]) or JAVA_METHOD.search(lines[index]) or PHP_FUNCTION.search(lines[index])
            ),
            len(lines) + 1,
        )
        return max(line_no, next_function - 1)

    def _summarize_function_name(self, name: str, args: str) -> str:
        words = re.sub(r"([a-z])([A-Z])", r"\1 \2", name).replace("_", " ")
        return f"Function '{words}' with parameters ({args})."
