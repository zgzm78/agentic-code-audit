from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from .models import CallEdgeSummary, FunctionSummary, RouteSummary, SemanticIndex


ENTRY_NAME_PATTERNS = (
    "main",
    "route",
    "servehttp",
)

EXTERNAL_SOURCE_PATTERNS = (
    r"request\.(?:args|form|json|values|GET|POST)",
    r"request\s*\[",
    r"req\.(?:query|body|params)",
    r"req\s*\[",
    r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)",
    r"\bargv\b|\bargc\b",
    r"\bstdin\b",
    r"\binput\s*\(",
    r"\bread\s*\(",
    r"\bfread\s*\(",
    r"\brecv\s*\(",
    r"\bgetenv\s*\(",
    r"\bURL\.Query\s*\(",
    r"\bFormValue\s*\(",
    r"\bgetParameter\s*\(",
    r"\bgetDataByRange\s*\(",
    r"\bio_->read\s*\(",
    r"\breadOrThrow\s*\(",
)

SOURCE_LIKE_TAGS = {"source", "route", "entry"}


@dataclass
class InterproceduralSlice:
    source: str = ""
    parameter: str = ""
    argument: str = ""
    caller: str = ""
    caller_file: str = ""
    line: int = 0
    call_chain: list[str] = field(default_factory=list)
    caller_paths: list[list[str]] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)
    status: str = "unresolved"
    confidence: float = 0.0
    evidence: list[dict[str, Any]] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    backends: list[str] = field(default_factory=lambda: ["semantic_call_graph"])

    @property
    def linked(self) -> bool:
        return self.status in {"resolved_source", "entry_parameter"}

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "parameter": self.parameter,
            "argument": self.argument,
            "caller": self.caller,
            "caller_file": self.caller_file,
            "line": self.line,
            "call_chain": list(self.call_chain),
            "caller_paths": [list(path) for path in self.caller_paths],
            "entry_points": list(self.entry_points),
            "status": self.status,
            "confidence": self.confidence,
            "evidence": [dict(item) for item in self.evidence],
            "gaps": list(self.gaps),
            "backends": list(self.backends),
        }


class ProjectCallGraph:
    """Project-level reverse call graph built from the semantic index.

    Call edges in the current semantic index are lexical facts and often miss
    import/type resolution. This wrapper keeps all matching cross-file caller
    facts but ranks same-file and higher-confidence edges first. It gives the
    slicer a stable, language-neutral API instead of scattering ad hoc caller
    searches across mining code.
    """

    def __init__(self, semantic_index: SemanticIndex) -> None:
        self.semantic_index = semantic_index
        self.functions = list(semantic_index.functions or [])
        self.edges = list(semantic_index.call_edges or [])
        self.routes = list(semantic_index.routes or [])
        self._function_by_name: dict[str, list[FunctionSummary]] = {}
        for summary in self.functions:
            keys = {summary.name, self.base_name(summary.name)}
            for key in keys:
                self._function_by_name.setdefault(self._norm(key), []).append(summary)

    def function_summaries(self, name: str, file_path: str = "") -> list[FunctionSummary]:
        candidates = list(self._function_by_name.get(self._norm(name), []))
        candidates.extend(
            item for item in self._function_by_name.get(self._norm(self.base_name(name)), []) if item not in candidates
        )
        if file_path:
            candidates.sort(key=lambda item: 0 if item.file_path == file_path else 1)
        return candidates

    def parameters_for(self, name: str, file_path: str = "") -> list[str]:
        for summary in self.function_summaries(name, file_path):
            if summary.parameters:
                return list(summary.parameters)
        return []

    def incoming_edges(self, callee: str, file_path: str = "") -> list[CallEdgeSummary]:
        edges = [edge for edge in self.edges if self.same_function(edge.callee, callee)]
        edges.sort(
            key=lambda edge: (
                0 if file_path and edge.file_path == file_path else 1,
                -float(edge.confidence or 0.0),
                edge.file_path,
                edge.line,
            )
        )
        return edges

    def caller_paths(
        self,
        function: str,
        file_path: str = "",
        *,
        max_depth: int = 8,
        max_paths: int = 64,
    ) -> list[list[str]]:
        if not function:
            return []
        paths: list[list[str]] = []
        queue: list[tuple[list[str], str]] = [([function], file_path)]
        seen: set[str] = {self._path_key([function], file_path)}
        while queue and len(paths) < max_paths:
            path, current_file = queue.pop(0)
            current = path[0]
            for edge in self.incoming_edges(current, current_file):
                caller = edge.caller
                if not caller or any(self.same_function(caller, item) for item in path):
                    continue
                next_path = [caller, *path]
                key = self._path_key(next_path, edge.file_path)
                if key in seen:
                    continue
                seen.add(key)
                paths.append(next_path)
                if len(next_path) < max_depth:
                    queue.append((next_path, edge.file_path))
        paths.sort(key=lambda path: (self._entry_rank(path), len(path), path))
        return paths

    def call_chain_for(self, function: str, file_path: str, sink: str = "") -> list[str]:
        paths = self.caller_paths(function, file_path)
        best = paths[0] if paths else ([function] if function else [])
        route = self.route_for_path(best)
        chain = [route, *best] if route else list(best)
        if sink and (not chain or chain[-1] != sink):
            chain.append(sink)
        return [item for item in chain if item]

    def route_for_path(self, path: list[str]) -> str:
        if not path:
            return ""
        for function in path:
            for route in self.routes:
                if self.same_function(route.handler, function):
                    return self.route_label(route)
        return ""

    def entry_points_for_paths(self, paths: list[list[str]]) -> list[str]:
        entries: list[str] = []
        for path in paths:
            route = self.route_for_path(path)
            if route:
                entries.append(route)
            if path:
                first = path[0]
                summaries = self.function_summaries(first)
                if any(self._looks_like_entry(summary) for summary in summaries) or self._looks_like_entry_name(first):
                    entries.append(first)
        return list(dict.fromkeys(entries))

    def edge_facts_for_path(self, path: list[str]) -> list[dict[str, Any]]:
        facts: list[dict[str, Any]] = []
        for caller, callee in zip(path, path[1:]):
            edge = next(
                (
                    item
                    for item in self.edges
                    if self.same_function(item.caller, caller) and self.same_function(item.callee, callee)
                ),
                None,
            )
            if not edge:
                continue
            facts.append(
                {
                    "caller": edge.caller,
                    "callee": edge.callee,
                    "file_path": edge.file_path,
                    "line": edge.line,
                    "arguments": list(edge.arguments),
                    "confidence": edge.confidence,
                    "resolution": edge.resolution,
                }
            )
        return facts

    def route_label(self, route: RouteSummary) -> str:
        method = (route.method or "ANY").upper()
        path = route.route or "/"
        return f"{method} {path}"

    def same_function(self, left: str, right: str) -> bool:
        if not left or not right:
            return False
        left_norm = self._norm(left)
        right_norm = self._norm(right)
        left_base = self._norm(self.base_name(left))
        right_base = self._norm(self.base_name(right))
        return left_norm == right_norm or left_base == right_base

    def base_name(self, name: str) -> str:
        normalized = re.sub(r"\s+", "", name or "")
        normalized = normalized.split("::")[-1]
        normalized = normalized.split("->")[-1]
        normalized = normalized.split(".")[-1]
        return normalized

    def _entry_rank(self, path: list[str]) -> int:
        if self.route_for_path(path):
            return 0
        if path and self._looks_like_entry_name(path[0]):
            return 1
        return 2

    def _looks_like_entry(self, summary: FunctionSummary) -> bool:
        return self._looks_like_entry_name(summary.name)

    def _looks_like_entry_name(self, name: str) -> bool:
        lowered = self.base_name(name).lower()
        return any(token in lowered for token in ENTRY_NAME_PATTERNS)

    def _path_key(self, path: list[str], file_path: str) -> str:
        digest = hashlib.sha1("->".join(path).encode("utf-8")).hexdigest()[:8]
        return f"{file_path}:{digest}:{len(path)}"

    def _norm(self, name: str) -> str:
        return re.sub(r"\s+", "", name or "").lower()


class InterproceduralSlicer:
    """Resolve parameter-only local slices through project call edges."""

    def analyze(
        self,
        *,
        function_name: str,
        file_path: str,
        sink: str,
        variable_flow_status: str,
        source_variables: list[str],
        source: str,
        semantic_index: SemanticIndex,
    ) -> InterproceduralSlice:
        graph = ProjectCallGraph(semantic_index)
        caller_paths = graph.caller_paths(function_name, file_path)
        entry_points = graph.entry_points_for_paths(caller_paths)
        call_chain = graph.call_chain_for(function_name, file_path, sink)
        result = InterproceduralSlice(
            call_chain=call_chain,
            caller_paths=caller_paths,
            entry_points=entry_points,
            status="call_graph_only" if caller_paths else "unresolved",
            confidence=0.35 if caller_paths else 0.0,
            evidence=graph.edge_facts_for_path(caller_paths[0]) if caller_paths else [],
            gaps=[] if caller_paths else ["caller_not_found"],
        )
        if not function_name:
            result.gaps.append("missing_function_name")
            return result
        parameters = self._parameter_names(source_variables, source)
        if variable_flow_status != "parameter_flow" or not parameters:
            return result
        for parameter in parameters:
            resolved = self._resolve_parameter(
                graph,
                function=function_name,
                parameter=parameter,
                file_path=file_path,
                depth=8,
                seen=set(),
                trail=[function_name],
            )
            if resolved.linked:
                resolved.call_chain = graph.call_chain_for(function_name, file_path, sink) or result.call_chain
                resolved.caller_paths = result.caller_paths
                resolved.entry_points = result.entry_points
                resolved.backends = list(dict.fromkeys([*resolved.backends, "interprocedural_taint"]))
                return resolved
        if "caller_source_not_resolved" not in result.gaps:
            result.gaps.append("caller_source_not_resolved")
        return result

    def _resolve_parameter(
        self,
        graph: ProjectCallGraph,
        *,
        function: str,
        parameter: str,
        file_path: str,
        depth: int,
        seen: set[tuple[str, str, str]],
        trail: list[str],
    ) -> InterproceduralSlice:
        key = (graph.base_name(function), parameter, file_path)
        if depth <= 0 or key in seen:
            return InterproceduralSlice(status="unresolved", gaps=["max_depth_or_cycle"])
        seen.add(key)
        params = graph.parameters_for(function, file_path)
        parameter_index = self._parameter_index(parameter, params)
        if parameter_index is None:
            return InterproceduralSlice(status="unresolved", gaps=["parameter_not_in_signature"])

        best_unresolved = InterproceduralSlice(status="unresolved", gaps=["caller_source_not_resolved"])
        for edge in graph.incoming_edges(function, file_path):
            arguments = list(edge.arguments or [])
            if parameter_index >= len(arguments):
                continue
            argument = arguments[parameter_index].strip()
            source = self._source_from_argument(argument)
            fact = self._edge_fact(edge, function, parameter, argument)
            if source:
                return InterproceduralSlice(
                    source=source,
                    parameter=parameter,
                    argument=argument,
                    caller=edge.caller,
                    caller_file=edge.file_path,
                    line=edge.line,
                    call_chain=[edge.caller, *trail],
                    caller_paths=[[edge.caller, *trail]],
                    entry_points=[],
                    status="resolved_source",
                    confidence=min(0.95, 0.72 + float(edge.confidence or 0.0) / 5),
                    evidence=[fact],
                    gaps=[],
                    backends=["semantic_call_graph", "interprocedural_taint"],
                )
            caller_params = graph.parameters_for(edge.caller, edge.file_path)
            for identifier in self._argument_identifiers(argument):
                if identifier not in caller_params:
                    continue
                nested = self._resolve_parameter(
                    graph,
                    function=edge.caller,
                    parameter=identifier,
                    file_path=edge.file_path,
                    depth=depth - 1,
                    seen=seen,
                    trail=[edge.caller, *trail],
                )
                if nested.linked:
                    nested.evidence.insert(0, fact)
                    if not nested.argument:
                        nested.argument = argument
                    nested.parameter = nested.parameter or identifier
                    return nested
            if self._caller_is_entry_parameter(graph, edge.caller, edge.file_path, argument):
                return InterproceduralSlice(
                    source=f"entry_parameter:{edge.caller}.{argument}",
                    parameter=parameter,
                    argument=argument,
                    caller=edge.caller,
                    caller_file=edge.file_path,
                    line=edge.line,
                    call_chain=[edge.caller, *trail],
                    caller_paths=[[edge.caller, *trail]],
                    entry_points=[edge.caller],
                    status="entry_parameter",
                    confidence=0.58,
                    evidence=[fact],
                    gaps=["entry_parameter_source_not_materialized"],
                    backends=["semantic_call_graph", "interprocedural_taint"],
                )
        return best_unresolved

    def _parameter_names(self, source_variables: list[str], source: str) -> list[str]:
        values = [*source_variables]
        if source.startswith("parameter:"):
            values.append(source.removeprefix("parameter:"))
        return [item.removeprefix("parameter:") for item in dict.fromkeys(values) if item]

    def _parameter_index(self, parameter: str, params: list[str]) -> int | None:
        if not params:
            return 0
        cleaned = [self._clean_parameter(item) for item in params]
        if parameter in cleaned:
            return cleaned.index(parameter)
        if len(cleaned) == 1:
            return 0
        return None

    def _clean_parameter(self, value: str) -> str:
        names = re.findall(r"[A-Za-z_$][A-Za-z0-9_$]*", value or "")
        return names[-1] if names else value

    def _source_from_argument(self, argument: str) -> str:
        for pattern in EXTERNAL_SOURCE_PATTERNS:
            match = re.search(pattern, argument or "", flags=re.IGNORECASE)
            if match:
                return argument.strip()
        return ""

    def _argument_identifiers(self, argument: str) -> list[str]:
        keywords = {
            "true", "false", "null", "none", "return", "sizeof", "new", "delete",
            "std", "string", "size_t", "int", "long", "char", "byte", "auto",
        }
        return [
            item
            for item in dict.fromkeys(re.findall(r"\b[A-Za-z_$][A-Za-z0-9_$]*\b", argument or ""))
            if item.lower() not in keywords
        ]

    def _caller_is_entry_parameter(self, graph: ProjectCallGraph, caller: str, file_path: str, argument: str) -> bool:
        params = set(graph.parameters_for(caller, file_path))
        if argument not in params:
            return False
        summaries = graph.function_summaries(caller, file_path)
        return any(graph._looks_like_entry(summary) for summary in summaries)

    def _edge_fact(self, edge: CallEdgeSummary, function: str, parameter: str, argument: str) -> dict[str, Any]:
        return {
            "kind": "argument_binding",
            "caller": edge.caller,
            "callee": edge.callee or function,
            "parameter": parameter,
            "argument": argument,
            "file_path": edge.file_path,
            "line": edge.line,
            "confidence": edge.confidence,
            "resolution": edge.resolution,
        }
