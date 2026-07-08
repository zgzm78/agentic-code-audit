from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

from ..config import Settings
from ..models import AgentEvent, FunctionSummary, RouteSummary, SemanticIndex, normalize_path, utc_now
from .profiler import IGNORED_DIRS


PY_FUNCTION = re.compile(r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*:")
JS_FUNCTION = re.compile(r"^\s*(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)")
PY_ROUTE = re.compile(r"@\w+\.route\(\s*['\"]([^'\"]+)['\"]")
EXPRESS_ROUTE = re.compile(r"\b(app|router)\.(get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]")

SOURCE_MARKERS = ("request.", "request[", "req.", "req[", "input(", "$_GET", "$_POST", "params", "query")
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
)


class SemanticAgent:
    def __init__(self, settings: Settings):
        self.settings = settings

    def run(self, target: Path) -> tuple[SemanticIndex, AgentEvent]:
        event = AgentEvent(agent="SemanticAgent", action="build_semantic_index", status="running")
        index = SemanticIndex()
        module_tags: dict[str, set[str]] = defaultdict(set)

        scanned = 0
        for path in target.rglob("*"):
            if scanned >= self.settings.max_files:
                break
            if any(part in IGNORED_DIRS for part in path.parts) or not path.is_file():
                continue
            try:
                if path.stat().st_size > self.settings.max_file_size:
                    continue
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            scanned += 1
            rel = normalize_path(path, target)
            self._extract_python(rel, text, index)
            self._extract_js(rel, text, index)
            self._extract_symbols(text, index, module_tags[rel])

        index.source_symbols = sorted(set(index.source_symbols))
        index.sink_symbols = sorted(set(index.sink_symbols))
        index.module_summaries = {
            path: f"tags={', '.join(sorted(tags))}" for path, tags in sorted(module_tags.items()) if tags
        }
        event.status = "completed"
        event.detail = (
            f"functions={len(index.functions)}; routes={len(index.routes)}; "
            f"sources={len(index.source_symbols)}; sinks={len(index.sink_symbols)}"
        )
        event.finished_at = utc_now()
        return index, event

    def _extract_python(self, rel: str, text: str, index: SemanticIndex) -> None:
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
        for line_no, line in enumerate(text.splitlines(), start=1):
            route = EXPRESS_ROUTE.search(line)
            if route:
                index.routes.append(
                    RouteSummary(
                        method=route.group(2).upper(),
                        route=route.group(3),
                        handler="<inline>",
                        file_path=rel,
                        line_start=line_no,
                    )
                )
            function = JS_FUNCTION.search(line)
            if function:
                name = function.group(1)
                args = function.group(2)
                index.functions.append(
                    FunctionSummary(
                        name=name,
                        file_path=rel,
                        line_start=line_no,
                        signature=f"function {name}({args})",
                        summary=self._summarize_function_name(name, args),
                        tags=self._line_tags(line),
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

    def _summarize_function_name(self, name: str, args: str) -> str:
        words = re.sub(r"([a-z])([A-Z])", r"\1 \2", name).replace("_", " ")
        return f"Function '{words}' with parameters ({args})."
