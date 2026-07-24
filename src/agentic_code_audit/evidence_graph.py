from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .dataflow import VariableFlowResult
from .models import (
    DangerousFunction,
    EvidenceEdge,
    EvidenceGraph,
    EvidenceNode,
    EvidencePath,
    RouteSummary,
    SemanticIndex,
)


LINKED_TAINT_STATUSES = {"direct", "propagated"}
PARAMETER_FLOW_STATUS = "parameter_flow"


@dataclass
class EvidenceGraphInput:
    graph_id: str
    target: Path
    anchor: DangerousFunction
    semantic_index: SemanticIndex
    variable_flow: VariableFlowResult | None = None
    call_chain: list[str] = field(default_factory=list)
    guards: list[str] = field(default_factory=list)
    sanitizers: list[str] = field(default_factory=list)
    missing_guards: list[str] = field(default_factory=list)
    sink_args: list[str] = field(default_factory=list)
    context: str = ""
    static_evidence: bool = False
    function_summary: dict[str, Any] = field(default_factory=dict)
    backward_slice: dict[str, Any] = field(default_factory=dict)
    interprocedural_flow: dict[str, Any] = field(default_factory=dict)


class EvidenceGraphBuilder:
    """Build sink-centered evidence graphs from verified local facts.

    The graph is intentionally provenance-aware: this builder only emits fact
    edges from the current AST/lexical analysis and semantic index. LLM-created
    hypotheses should be added by a later backend with provenance explicitly set
    to ``llm_hypothesis`` and must never be counted as fact paths.
    """

    def build(self, data: EvidenceGraphInput) -> EvidenceGraph:
        if data.static_evidence:
            return self._static_graph(data)

        graph = EvidenceGraph(
            id=data.graph_id,
            status="sink_only",
            guards=list(data.guards),
            sanitizers=list(data.sanitizers),
            gaps=list(data.variable_flow.gaps if data.variable_flow else []),
            backends=["semantic_index", "local_dataflow"],
            metadata={
                "anchor_id": data.anchor.id,
                "dangerous_api": data.anchor.dangerous_api,
                "rule_id": data.anchor.rule_id,
                "sink_args": list(data.sink_args),
                "function_summary": self._compact_function_summary(data.function_summary),
                "backward_slice": self._compact_backward_slice(data.backward_slice),
                "interprocedural_flow": self._compact_interprocedural_flow(data.interprocedural_flow),
            },
        )
        if data.backward_slice:
            graph.backends.append("sink_backward_slice")
        if data.interprocedural_flow:
            graph.backends.extend(
                item
                for item in list(data.interprocedural_flow.get("backends") or ["interprocedural_taint"])
                if item not in graph.backends
            )
        sink_func_id = self._add_node(
            graph,
            "sink_function",
            data.anchor.function_name or data.anchor.file_path,
            file_path=data.anchor.file_path,
            line=data.anchor.line_start,
            function=data.anchor.function_name,
            detail="Function containing the dangerous sink.",
        )
        sink_api_id = self._add_node(
            graph,
            "sink",
            data.anchor.sink or data.anchor.dangerous_api,
            file_path=data.anchor.file_path,
            line=data.anchor.line_start,
            function=data.anchor.function_name,
            detail=data.anchor.snippet,
        )
        graph.sink_node_id = sink_api_id
        graph.sinks.append(sink_api_id)
        self._add_edge(graph, sink_func_id, sink_api_id, "contains_sink", "contains sink", data.anchor.snippet)

        entry_node_id = ""
        for route in self._matching_routes(data):
            route_id = self._add_route_node(graph, route)
            self._add_edge(graph, route_id, sink_func_id, "calls", "route reaches function", route.handler)
            entry_node_id = entry_node_id or route_id
        call_chain_entry_id = self._add_call_chain_nodes(graph, sink_func_id, data)
        entry_node_id = entry_node_id or call_chain_entry_id
        interproc_entry_id = self._add_interprocedural_nodes(graph, sink_api_id, data)
        entry_node_id = entry_node_id or interproc_entry_id

        for guard in data.guards[:8]:
            guard_id = self._add_node(
                graph,
                "guard",
                guard,
                file_path=data.anchor.file_path,
                line=data.anchor.line_start,
                function=data.anchor.function_name,
                detail="Control guard observed near the sink.",
            )
            self._add_edge(graph, guard_id, sink_api_id, "guards", "guard observed", guard)

        for sanitizer in data.sanitizers[:8]:
            sanitizer_id = self._add_node(
                graph,
                "sanitizer",
                sanitizer,
                file_path=data.anchor.file_path,
                line=data.anchor.line_start,
                function=data.anchor.function_name,
                detail="Sanitizer or escaping operation observed near the sink.",
            )
            self._add_edge(graph, sanitizer_id, sink_api_id, "sanitizes", "sanitizer observed", sanitizer)

        self._add_backward_slice_nodes(graph, sink_api_id, data)

        flow = data.variable_flow
        source_node_id = ""
        if flow and flow.steps:
            previous_id = ""
            path_node_ids: list[str] = []
            path_edge_ids: list[int] = []
            for index, step in enumerate(flow.steps):
                node_type = "source" if step.operation == "source" else ("sink" if step.operation == "sink" else "variable")
                if step.operation == "parameter":
                    node_type = "parameter"
                node_id = self._add_node(
                    graph,
                    node_type,
                    step.variable,
                    file_path=data.anchor.file_path,
                    line=step.line,
                    function=data.anchor.function_name,
                    detail=step.expression,
                    facts={"operation": step.operation},
                )
                if index == 0 and node_type in {"source", "parameter"}:
                    source_node_id = node_id
                    graph.sources.append(node_id)
                if previous_id:
                    edge_id = self._add_edge(
                        graph,
                        previous_id,
                        node_id,
                        "data_dep",
                        step.operation,
                        step.expression,
                        provenance="fact_ast" if data.anchor.language.lower() == "python" else "fact_lexical",
                    )
                    path_edge_ids.append(edge_id)
                previous_id = node_id
                path_node_ids.append(node_id)
            if previous_id and previous_id != sink_api_id:
                edge_id = self._add_edge(graph, previous_id, sink_api_id, "reaches_sink", "reaches sink", data.anchor.snippet)
                path_edge_ids.append(edge_id)
                path_node_ids.append(sink_api_id)
            graph.paths.append(
                EvidencePath(
                    id=self._path_id(data.graph_id, "taint", path_node_ids),
                    kind="taint",
                    status=self._path_status(flow.status),
                    node_ids=path_node_ids,
                    edge_ids=path_edge_ids,
                    source_node_id=source_node_id,
                    sink_node_id=sink_api_id,
                    entry_node_id=entry_node_id,
                    gaps=list(flow.gaps),
                    provenance="fact_ast" if data.anchor.language.lower() == "python" else "fact_lexical",
                    confidence=self._path_confidence(flow.status, entry_node_id),
                )
            )

        graph.status = self._graph_status(graph, flow, entry_node_id)
        graph.confidence = self._graph_confidence(graph.status, graph.paths, data.missing_guards)
        graph.fact_count = len([edge for edge in graph.edges if not edge.provenance.startswith("llm_")])
        graph.hypothesis_count = len([edge for edge in graph.edges if edge.provenance.startswith("llm_")])
        graph.gaps = list(dict.fromkeys([*graph.gaps, *self._status_gaps(graph.status, data), *self._backward_slice_gaps(data)]))
        return graph

    def _static_graph(self, data: EvidenceGraphInput) -> EvidenceGraph:
        graph = EvidenceGraph(
            id=data.graph_id,
            status="static_evidence",
            gaps=[],
            fact_count=1,
            confidence=data.anchor.confidence,
            backends=[data.anchor.tool or "static_tool"],
            metadata={
                "anchor_id": data.anchor.id,
                "kind": data.anchor.kind,
                "rule_id": data.anchor.rule_id,
            },
        )
        sink_id = self._add_node(
            graph,
            data.anchor.kind or "static_evidence",
            data.anchor.sink or data.anchor.dangerous_api,
            file_path=data.anchor.file_path,
            line=data.anchor.line_start,
            detail=data.context or data.anchor.snippet,
            facts={"risk_domain": data.anchor.risk_domain},
        )
        graph.sink_node_id = sink_id
        graph.sinks.append(sink_id)
        return graph

    def _matching_routes(self, data: EvidenceGraphInput) -> list[RouteSummary]:
        anchor = data.anchor
        chain = [item for item in data.call_chain if item]
        matches = [
            route
            for route in data.semantic_index.routes
            if route.file_path == anchor.file_path
            and (
                self._same_label(route.handler, anchor.function_name or "")
                or any(self._same_label(route.handler, item) for item in chain)
                or (not chain and route.line_start <= anchor.line_start)
            )
        ]
        return matches[-3:]

    def _add_call_chain_nodes(self, graph: EvidenceGraph, sink_func_id: str, data: EvidenceGraphInput) -> str:
        items = [item for item in data.call_chain if item and item != data.anchor.sink]
        if not items:
            return ""
        previous_id = ""
        entry_node_id = ""
        for index, item in enumerate(items[:12]):
            if self._same_label(item, data.anchor.function_name or ""):
                node_id = sink_func_id
            else:
                node_type = "entry" if self._looks_like_route(item) else "function"
                node_id = self._add_node(
                    graph,
                    node_type,
                    item,
                    file_path=data.anchor.file_path,
                    line=data.anchor.line_start if node_type == "function" and self._same_label(item, data.anchor.function_name or "") else None,
                    function=item if node_type == "function" else "",
                    detail="Call-chain fact from semantic call graph.",
                    facts={"call_chain_index": index},
                )
                if node_type == "entry":
                    entry_node_id = entry_node_id or node_id
                    graph.sources.append(node_id)
            if previous_id and previous_id != node_id:
                self._add_edge(graph, previous_id, node_id, "calls", "call graph edge", item, provenance="fact_call_graph", confidence=0.7)
            previous_id = node_id
        if previous_id and previous_id != sink_func_id:
            self._add_edge(graph, previous_id, sink_func_id, "calls", "call graph reaches sink function", data.anchor.function_name, provenance="fact_call_graph", confidence=0.7)
        return entry_node_id

    def _add_interprocedural_nodes(
        self,
        graph: EvidenceGraph,
        sink_api_id: str,
        data: EvidenceGraphInput,
    ) -> str:
        flow = data.interprocedural_flow if isinstance(data.interprocedural_flow, dict) else {}
        if not flow:
            return ""
        source = str(flow.get("source") or "")
        status = str(flow.get("status") or "")
        if not source and not flow.get("caller_paths") and not flow.get("evidence"):
            return ""
        call_chain = [str(item) for item in list(flow.get("call_chain") or data.call_chain or []) if item]
        entry_points = [str(item) for item in list(flow.get("entry_points") or []) if item]
        evidence = [item for item in list(flow.get("evidence") or []) if isinstance(item, dict)]
        confidence = float(flow.get("confidence") or 0.55)
        path_node_ids: list[str] = []
        path_edge_ids: list[int] = []
        entry_node_id = ""
        previous_id = ""

        if source:
            source_id = self._add_node(
                graph,
                "source",
                source,
                file_path=str(flow.get("caller_file") or data.anchor.file_path),
                line=self._int(flow.get("line")),
                detail="External source resolved through interprocedural parameter propagation.",
                facts={"parameter": flow.get("parameter", ""), "argument": flow.get("argument", "")},
            )
            graph.sources.append(source_id)
            path_node_ids.append(source_id)
            previous_id = source_id

        if entry_points:
            entry_id = self._add_node(
                graph,
                "entry",
                entry_points[0],
                file_path=str(flow.get("caller_file") or data.anchor.file_path),
                detail="Entry point resolved from project call graph.",
                facts={"entry_points": entry_points[:8]},
            )
            entry_node_id = entry_id
            graph.sources.append(entry_id)
            if previous_id and previous_id != entry_id:
                path_edge_ids.append(
                    self._add_edge(
                        graph,
                        previous_id,
                        entry_id,
                        "enters",
                        "enters program",
                        entry_points[0],
                        provenance="fact_interprocedural",
                        confidence=confidence,
                    )
                )
            previous_id = entry_id
            path_node_ids.append(entry_id)

        for index, item in enumerate(call_chain[:20]):
            if item == source or item == data.anchor.sink:
                continue
            node_type = "entry" if self._looks_like_route(item) else "function"
            node_id = self._add_node(
                graph,
                node_type,
                item,
                file_path=data.anchor.file_path,
                line=data.anchor.line_start if self._same_label(item, data.anchor.function_name or "") else None,
                function=item if node_type == "function" else "",
                detail="Interprocedural call graph node.",
                facts={"call_chain_index": index},
            )
            if node_type == "entry":
                entry_node_id = entry_node_id or node_id
                graph.sources.append(node_id)
            if previous_id and previous_id != node_id:
                path_edge_ids.append(
                    self._add_edge(
                        graph,
                        previous_id,
                        node_id,
                        "calls",
                        "interprocedural call",
                        item,
                        provenance="fact_interprocedural",
                        confidence=confidence,
                    )
                )
            previous_id = node_id
            path_node_ids.append(node_id)

        for item in evidence[:8]:
            binding_id = self._add_node(
                graph,
                "argument_binding",
                f"{item.get('callee', '')}.{item.get('parameter', '')} <- {item.get('argument', '')}",
                file_path=str(item.get("file_path") or data.anchor.file_path),
                line=self._int(item.get("line")),
                detail="Caller argument bound to callee parameter.",
                facts=dict(item),
            )
            if previous_id and previous_id != binding_id:
                path_edge_ids.append(
                    self._add_edge(
                        graph,
                        previous_id,
                        binding_id,
                        "argument_binding",
                        "binds parameter",
                        str(item.get("argument") or ""),
                        provenance="fact_interprocedural",
                        confidence=float(item.get("confidence") or confidence),
                    )
                )
            previous_id = binding_id
            path_node_ids.append(binding_id)

        if previous_id and previous_id != sink_api_id:
            path_edge_ids.append(
                self._add_edge(
                    graph,
                    previous_id,
                    sink_api_id,
                    "reaches_sink",
                    "interprocedural flow reaches sink",
                    data.anchor.snippet,
                    provenance="fact_interprocedural",
                    confidence=confidence,
                )
            )
            path_node_ids.append(sink_api_id)

        if path_node_ids:
            graph.paths.append(
                EvidencePath(
                    id=self._path_id(data.graph_id, "interprocedural", path_node_ids),
                    kind="interprocedural_taint",
                    status="proven" if status in {"resolved_source", "entry_parameter"} else "reachable",
                    node_ids=path_node_ids,
                    edge_ids=path_edge_ids,
                    source_node_id=path_node_ids[0] if source else "",
                    sink_node_id=sink_api_id,
                    entry_node_id=entry_node_id,
                    gaps=list(flow.get("gaps") or []),
                    provenance="fact_interprocedural",
                    confidence=confidence,
                )
            )
        return entry_node_id

    def _looks_like_route(self, value: str) -> bool:
        text = value.strip()
        return bool(text and "/" in text and (" " in text or text.startswith("/")))

    def _same_label(self, left: str, right: str) -> bool:
        if not left or not right:
            return False
        left_norm = left.replace(" ", "")
        right_norm = right.replace(" ", "")
        return left_norm == right_norm or left_norm.split("::")[-1] == right_norm.split("::")[-1]

    def _add_route_node(self, graph: EvidenceGraph, route: RouteSummary) -> str:
        label = f"{route.method} {route.route}"
        return self._add_node(
            graph,
            "entry",
            label,
            file_path=route.file_path,
            line=route.line_start,
            function=route.handler,
            detail="Framework route entry from the semantic index.",
            facts={"entry_kind": "http_route"},
        )

    def _add_node(
        self,
        graph: EvidenceGraph,
        node_type: str,
        label: str,
        *,
        file_path: str = "",
        line: int | None = None,
        function: str = "",
        detail: str = "",
        facts: dict[str, Any] | None = None,
    ) -> str:
        node_id = self._node_id(node_type, label, file_path, line, function)
        if not any(node.id == node_id for node in graph.nodes):
            graph.nodes.append(
                EvidenceNode(
                    id=node_id,
                    type=node_type,
                    label=label,
                    file_path=file_path,
                    line=line,
                    function=function,
                    detail=detail,
                    facts=dict(facts or {}),
                )
            )
        return node_id

    def _add_edge(
        self,
        graph: EvidenceGraph,
        source: str,
        target: str,
        edge_type: str,
        label: str,
        evidence: str,
        *,
        provenance: str = "fact_ast",
        confidence: float = 1.0,
    ) -> int:
        edge = EvidenceEdge(
            source=source,
            target=target,
            type=edge_type,
            label=label,
            evidence=evidence,
            provenance=provenance,
            confidence=confidence,
        )
        graph.edges.append(edge)
        return len(graph.edges) - 1

    def _add_backward_slice_nodes(
        self,
        graph: EvidenceGraph,
        sink_api_id: str,
        data: EvidenceGraphInput,
    ) -> None:
        backward = data.backward_slice if isinstance(data.backward_slice, dict) else {}
        if not backward:
            return
        role_args = backward.get("role_args") if isinstance(backward.get("role_args"), dict) else {}
        for role, expression in list(role_args.items())[:8]:
            role_id = self._add_node(
                graph,
                f"sink_arg_{role}",
                f"{role}: {expression}",
                file_path=data.anchor.file_path,
                line=data.anchor.line_start,
                function=data.anchor.function_name,
                detail=str(expression),
                facts={"role": role},
            )
            self._add_edge(graph, role_id, sink_api_id, "sink_argument", role, str(expression), provenance="fact_backward_slice")
        dependencies = backward.get("dependencies") if isinstance(backward.get("dependencies"), list) else []
        for item in dependencies[:16]:
            if not isinstance(item, dict):
                continue
            symbol = str(item.get("symbol") or "")
            expression = str(item.get("expression") or "")
            line = self._int(item.get("line"))
            dep_id = self._add_node(
                graph,
                "definition",
                symbol or expression[:80],
                file_path=data.anchor.file_path,
                line=line,
                function=data.anchor.function_name,
                detail=expression,
                facts={"role": item.get("role", "")},
            )
            self._add_edge(graph, dep_id, sink_api_id, "data_dep", str(item.get("role") or "dependency"), expression, provenance="fact_backward_slice")
        for field_name in list(backward.get("field_reads") or [])[:16]:
            field_id = self._add_node(
                graph,
                "field_read",
                str(field_name),
                file_path=data.anchor.file_path,
                line=data.anchor.line_start,
                function=data.anchor.function_name,
                detail="Object/member field read in backward slice.",
            )
            self._add_edge(graph, field_id, sink_api_id, "field_dep", "field read", str(field_name), provenance="fact_backward_slice")
        for missing in list(backward.get("missing_guards") or [])[:8]:
            guard_id = self._add_node(
                graph,
                "missing_guard",
                str(missing),
                file_path=data.anchor.file_path,
                line=data.anchor.line_start,
                function=data.anchor.function_name,
                detail="Missing guard inferred from sink argument backward slice.",
            )
            self._add_edge(graph, guard_id, sink_api_id, "missing_guard", "missing guard", str(missing), provenance="fact_backward_slice", confidence=0.75)

    def _graph_status(
        self,
        graph: EvidenceGraph,
        flow: VariableFlowResult | None,
        entry_node_id: str,
    ) -> str:
        if flow and flow.status in LINKED_TAINT_STATUSES:
            return "entry_tainted_flow" if entry_node_id else "local_tainted_flow"
        if flow and flow.status == PARAMETER_FLOW_STATUS:
            return "entry_parameter_flow" if entry_node_id else "parameter_flow_unresolved"
        if entry_node_id:
            return "entry_reachable_no_taint"
        if flow and flow.gaps:
            return "unlinked_sink"
        return "sink_only"

    def _path_status(self, flow_status: str) -> str:
        if flow_status in LINKED_TAINT_STATUSES:
            return "proven"
        if flow_status == PARAMETER_FLOW_STATUS:
            return "source_unresolved"
        return "unlinked"

    def _path_confidence(self, flow_status: str, entry_node_id: str) -> float:
        if flow_status in LINKED_TAINT_STATUSES:
            return 0.85 if entry_node_id else 0.75
        if flow_status == PARAMETER_FLOW_STATUS:
            return 0.55 if entry_node_id else 0.45
        return 0.2

    def _graph_confidence(
        self,
        status: str,
        paths: list[EvidencePath],
        missing_guards: list[str],
    ) -> float:
        base = {
            "entry_tainted_flow": 0.82,
            "local_tainted_flow": 0.72,
            "entry_parameter_flow": 0.62,
            "parameter_flow_unresolved": 0.45,
            "entry_reachable_no_taint": 0.35,
            "unlinked_sink": 0.2,
            "sink_only": 0.12,
            "static_evidence": 0.5,
        }.get(status, 0.2)
        if paths:
            base = max(base, max(path.confidence for path in paths))
        if missing_guards and status in {"entry_tainted_flow", "local_tainted_flow"}:
            base = min(0.95, base + 0.06)
        return round(base, 4)

    def _status_gaps(self, status: str, data: EvidenceGraphInput) -> list[str]:
        gaps: list[str] = []
        interproc = data.interprocedural_flow if isinstance(data.interprocedural_flow, dict) else {}
        interproc_status = str(interproc.get("status") or "")
        if status in {"sink_only", "unlinked_sink"}:
            gaps.append("source_to_sink_taint_not_proven")
        if status in {"parameter_flow_unresolved", "entry_parameter_flow"} and interproc_status not in {"resolved_source", "entry_parameter"}:
            gaps.append("caller_source_not_resolved")
        if status in {"local_tainted_flow", "parameter_flow_unresolved", "unlinked_sink", "sink_only"}:
            gaps.append("external_entry_not_resolved")
        if data.missing_guards:
            gaps.extend(f"missing_guard:{item}" for item in data.missing_guards[:4])
        return gaps

    def _backward_slice_gaps(self, data: EvidenceGraphInput) -> list[str]:
        backward = data.backward_slice if isinstance(data.backward_slice, dict) else {}
        return [f"missing_guard:{item}" for item in list(backward.get("missing_guards") or [])[:8]]

    def _compact_function_summary(self, value: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(value, dict):
            return {}
        return {
            "name": value.get("name", ""),
            "line_start": value.get("line_start"),
            "line_end": value.get("line_end"),
            "parameters": list(value.get("parameters") or [])[:8],
            "calls": list(value.get("calls") or [])[:12],
            "field_reads": list(value.get("field_reads") or [])[:12],
            "field_writes": list(value.get("field_writes") or [])[:12],
        }

    def _compact_backward_slice(self, value: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(value, dict):
            return {}
        return {
            "sink_args": list(value.get("sink_args") or [])[:8],
            "role_args": dict(value.get("role_args") or {}),
            "field_reads": list(value.get("field_reads") or [])[:12],
            "missing_guards": list(value.get("missing_guards") or [])[:8],
            "summary_steps": list(value.get("summary_steps") or [])[:12],
        }

    def _compact_interprocedural_flow(self, value: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(value, dict):
            return {}
        return {
            "source": value.get("source", ""),
            "parameter": value.get("parameter", ""),
            "argument": value.get("argument", ""),
            "caller": value.get("caller", ""),
            "caller_file": value.get("caller_file", ""),
            "line": value.get("line"),
            "status": value.get("status", ""),
            "confidence": value.get("confidence", 0.0),
            "entry_points": list(value.get("entry_points") or [])[:8],
            "caller_paths": [list(path)[:20] for path in list(value.get("caller_paths") or [])[:8] if isinstance(path, list)],
            "evidence": [dict(item) for item in list(value.get("evidence") or [])[:8] if isinstance(item, dict)],
        }

    def _int(self, value: Any) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _node_id(
        self,
        node_type: str,
        label: str,
        file_path: str,
        line: int | None,
        function: str,
    ) -> str:
        raw = f"{node_type}:{label}:{file_path}:{line or ''}:{function}"
        digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:10]
        return f"{node_type}_{digest}"

    def _path_id(self, graph_id: str, kind: str, node_ids: list[str]) -> str:
        digest = hashlib.sha1("|".join(node_ids).encode("utf-8")).hexdigest()[:10]
        return f"{graph_id}_{kind}_{digest}"
