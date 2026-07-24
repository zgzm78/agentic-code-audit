"""Mining debug report generator - produces mining-debug.json from MiningResult."""

from __future__ import annotations

from collections import Counter
from typing import Any


def generate_mining_debug(mining_result: Any) -> dict[str, Any]:
    """Build a comprehensive debug report from a MiningResult."""

    # --- tool anchors ---
    tool_anchor_count: dict[str, int] = Counter()
    anchor_domain_count: dict[str, int] = Counter()
    for df in mining_result.dangerous_functions or []:
        tool_anchor_count[str(getattr(df, "tool", "unknown"))] += 1
        anchor_domain_count[str(getattr(df, "risk_domain", "") or getattr(df, "anchor_category", "") or "unknown")] += 1

    # --- dangerous function kinds ---
    kind_count: dict[str, int] = Counter()
    for df in mining_result.dangerous_functions or []:
        kind_count[str(getattr(df, "kind", "unknown"))] += 1

    # --- slice counts by language and evidence graph status ---
    slice_lang_count: dict[str, int] = Counter()
    slice_status_count: dict[str, int] = Counter()
    flow_status_count: dict[str, int] = Counter()
    backward_slice_count = 0
    backward_missing_guards: dict[str, int] = Counter()
    backward_role_args: dict[str, int] = Counter()
    backward_field_reads: dict[str, int] = Counter()
    for sl in mining_result.program_slices or []:
        fp = str(getattr(sl, "file_path", ""))
        suffix = fp.rsplit(".", 1)[-1] if "." in fp else "unknown"
        lang = {
            "py": "Python",
            "js": "JavaScript",
            "jsx": "JavaScript",
            "ts": "TypeScript",
            "tsx": "TypeScript",
            "c": "C",
            "cc": "C++",
            "cpp": "C++",
            "cxx": "C++",
            "h": "C/C++",
            "hpp": "C/C++",
            "go": "Go",
            "java": "Java",
            "php": "PHP",
            "rs": "Rust",
        }.get(suffix.lower(), suffix)
        slice_lang_count[lang] += 1
        evidence_graph = getattr(sl, "evidence_graph", None)
        status = str(getattr(sl, "slice_status", "") or getattr(evidence_graph, "status", "") or "unknown")
        slice_status_count[status] += 1
        flow_status_count[str(getattr(sl, "flow_status", "") or "unknown")] += 1
        backward = getattr(sl, "backward_slice", {}) or {}
        if isinstance(backward, dict) and backward:
            backward_slice_count += 1
            for item in list(backward.get("missing_guards") or []):
                backward_missing_guards[str(item)] += 1
            for role in (backward.get("role_args") or {}).keys():
                backward_role_args[str(role)] += 1
            for field in list(backward.get("field_reads") or []):
                backward_field_reads[str(field)] += 1

    # --- candidate validity ---
    valid_count = 0
    invalid_count = 0
    needs_context_count = 0
    rejected_count = 0
    invalid_reasons: dict[str, int] = Counter()
    candidate_source_count: dict[str, int] = Counter()
    candidate_domain_count: dict[str, int] = Counter()
    investigation_candidates: list[dict[str, Any]] = []
    for c in mining_result.candidates or []:
        if getattr(c, "valid", True) and getattr(c, "validity", "valid") == "valid":
            valid_count += 1
        elif getattr(c, "validity", "") == "needs_context":
            needs_context_count += 1
            investigation_candidates.append(_candidate_debug_item(c))
            reason = getattr(c, "invalid_reason", "") or getattr(c, "validity", "")
            if reason:
                invalid_reasons[reason] += 1
        elif getattr(c, "validity", "") == "rejected":
            rejected_count += 1
            reason = getattr(c, "invalid_reason", "") or getattr(c, "validity", "")
            if reason:
                invalid_reasons[reason] += 1
        else:
            invalid_count += 1
            reason = getattr(c, "invalid_reason", "") or getattr(c, "validity", "")
            if reason:
                for part in reason.split(";"):
                    part = part.strip()
                    if part:
                        invalid_reasons[part] += 1
        src = getattr(c, "candidate_source", "unknown")
        candidate_source_count[src] += 1
        domain = getattr(c, "risk_domain", "") or "unknown"
        candidate_domain_count[str(domain)] += 1

    # --- finding distribution ---
    finding_type_count: dict[str, int] = Counter()
    finding_domain_count: dict[str, int] = Counter()
    finding_severity_count: dict[str, int] = Counter()
    finding_slice_status_count: dict[str, int] = Counter()
    verification_queue = 0
    for f in mining_result.findings or []:
        finding_type_count[str(getattr(f, "vulnerability_type", "unknown"))] += 1
        finding_domain_count[str(getattr(f, "risk_domain", "unknown"))] += 1
        finding_severity_count[str(getattr(f, "severity", "unknown"))] += 1
        evidence_graph = getattr(f, "evidence_graph", None)
        status = str(getattr(f, "slice_status", "") or getattr(evidence_graph, "status", "") or "unknown")
        finding_slice_status_count[status] += 1
        if getattr(f, "should_verify", False):
            verification_queue += 1

    # --- strategy ---
    strategy_data = mining_result.strategy if hasattr(mining_result, "strategy") else None
    strategy_data = strategy_data or {}
    exploration_log = strategy_data.get("exploration_log", []) if isinstance(strategy_data, dict) else []
    strategy_effects = getattr(mining_result, "strategy_effects", {}) or (
        strategy_data.get("strategy_effects", {}) if isinstance(strategy_data, dict) else {}
    )

    return {
        "tool_anchor_count_by_tool": dict(tool_anchor_count.most_common()),
        "anchor_count_by_risk_domain": dict(anchor_domain_count.most_common()),
        "dangerous_function_count_by_kind": dict(kind_count.most_common()),
        "signal_counts": getattr(mining_result, "signal_counts", {}) or {},
        "slice_count_by_language": dict(slice_lang_count.most_common()),
        "slice_status_distribution": dict(slice_status_count.most_common()),
        "flow_status_distribution": dict(flow_status_count.most_common()),
        "backward_slice_summary": {
            "slice_count": backward_slice_count,
            "missing_guards": dict(backward_missing_guards.most_common(20)),
            "role_args": dict(backward_role_args.most_common()),
            "field_reads": dict(backward_field_reads.most_common(20)),
        },
        "candidate_validity_breakdown": {
            "total": valid_count + needs_context_count + rejected_count + invalid_count,
            "valid": valid_count,
            "invalid": invalid_count,
            "needs_context": needs_context_count,
            "rejected": rejected_count,
        },
        "invalid_candidate_reasons": dict(invalid_reasons.most_common()),
        "candidate_source_distribution": dict(candidate_source_count.most_common()),
        "candidate_count_by_risk_domain": dict(candidate_domain_count.most_common()),
        "aggregation_input_count": len(mining_result.candidates or []),
        "aggregation_output_count": len(mining_result.aggregated_candidates or []),
        "investigation_candidates": sorted(
            investigation_candidates,
            key=lambda item: (
                item.get("slice_status") == "entry_tainted_flow",
                item.get("flow_status") in {"direct", "propagated"},
                float(item.get("confidence") or 0.0),
                len(item.get("evidence") or []),
            ),
            reverse=True,
        )[:80],
        "finding_count_by_type": dict(finding_type_count.most_common()),
        "finding_count_by_risk_domain": dict(finding_domain_count.most_common()),
        "finding_severity_distribution": dict(finding_severity_count.most_common()),
        "finding_slice_status_distribution": dict(finding_slice_status_count.most_common()),
        "verification_queue_count": verification_queue,
        "mining_director_strategy": strategy_data,
        "initial_strategy": strategy_data.get("initial_strategy", {}) if isinstance(strategy_data, dict) else {},
        "validated_strategy": strategy_data if isinstance(strategy_data, dict) else {},
        "rejected_strategy_items": strategy_data.get("rejected_strategy_items", []) if isinstance(strategy_data, dict) else [],
        "strategy_effects": strategy_effects,
        "exploration_log_summary": [
            {
                "tool": item.get("tool", ""),
                "success": item.get("success", False),
                "summary": item.get("summary", ""),
            }
            for item in exploration_log[:20]
            if isinstance(item, dict)
        ],
        "feedback_used": strategy_data.get("feedback_used", []) if isinstance(strategy_data, dict) else [],
        "budget": getattr(mining_result, "budget", {}) or {},
        "budget_usage": getattr(mining_result, "budget_usage", {}) or {},
    }


def _candidate_debug_item(candidate: Any) -> dict[str, Any]:
    return {
        "id": getattr(candidate, "id", ""),
        "slice_id": getattr(candidate, "slice_id", ""),
        "title": getattr(candidate, "title", ""),
        "vulnerability_type": getattr(candidate, "vulnerability_type", ""),
        "severity": getattr(candidate, "severity", ""),
        "file_path": getattr(candidate, "file_path", ""),
        "line_start": getattr(candidate, "line_start", None),
        "function_name": getattr(candidate, "function_name", ""),
        "source": getattr(candidate, "source", ""),
        "sink": getattr(candidate, "sink", ""),
        "confidence": getattr(candidate, "confidence", 0.0),
        "validity": getattr(candidate, "validity", ""),
        "candidate_state": getattr(candidate, "candidate_state", ""),
        "triage_verdict": getattr(candidate, "triage_verdict", ""),
        "triage_reason": getattr(candidate, "triage_reason", "") or getattr(candidate, "invalid_reason", ""),
        "missing_context": list(getattr(candidate, "triage_missing_context", []) or [])[:8],
        "trigger_conditions": list(getattr(candidate, "trigger_conditions", []) or [])[:8],
        "evidence": list(getattr(candidate, "evidence", []) or [])[:8],
        "flow_status": getattr(candidate, "flow_status", ""),
        "slice_status": getattr(candidate, "slice_status", ""),
        "analysis_backends": list(getattr(candidate, "analysis_backends", []) or [])[:8],
        "call_paths": [list(path)[:12] for path in list(getattr(candidate, "call_paths", []) or [])[:6]],
    }
