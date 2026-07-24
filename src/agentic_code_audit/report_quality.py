from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from .path_policy import PathPolicy


LINKED_FLOW_STATUSES = {"direct", "propagated"}
FACT_GRAPH_STATUSES = {"entry_tainted_flow", "local_tainted_flow"}
PARAMETER_GRAPH_STATUSES = {"entry_parameter_flow", "parameter_flow_unresolved"}
UNLINKED_GRAPH_STATUSES = {"sink_only", "unlinked_sink", "entry_reachable_no_taint"}
FLOW_GRAPH_STATUSES = FACT_GRAPH_STATUSES


@dataclass
class ReportQuality:
    report_id: str
    target: str
    created_at: str
    anchors: int = 0
    slices: int = 0
    candidates: int = 0
    aggregated_candidates: int = 0
    findings: int = 0
    source_code_findings: int = 0
    source_sink_complete: int = 0
    missing_source: int = 0
    missing_sink: int = 0
    call_chain_ge_3: int = 0
    linked_flow_findings: int = 0
    unlinked_flow_findings: int = 0
    tainted_graph_findings: int = 0
    parameter_graph_findings: int = 0
    unlinked_graph_findings: int = 0
    llm_triage_accepted: int = 0
    llm_triage_blocked: int = 0
    weak_evidence: int = 0
    noise_path_findings: int = 0
    low_priority_path_findings: int = 0
    dynamically_proven: int = 0
    risk_domains: dict[str, int] = field(default_factory=dict)
    graph_statuses: dict[str, int] = field(default_factory=dict)
    verification_statuses: dict[str, int] = field(default_factory=dict)
    proof_levels: dict[str, int] = field(default_factory=dict)

    @property
    def source_sink_rate(self) -> float:
        if not self.source_code_findings:
            return 0.0
        return self.source_sink_complete / self.source_code_findings

    @property
    def chain_rate(self) -> float:
        if not self.source_code_findings:
            return 0.0
        return self.call_chain_ge_3 / self.source_code_findings

    @property
    def linked_flow_rate(self) -> float:
        if not self.source_code_findings:
            return 0.0
        return self.linked_flow_findings / self.source_code_findings

    @property
    def tainted_graph_rate(self) -> float:
        if not self.source_code_findings:
            return 0.0
        return self.tainted_graph_findings / self.source_code_findings

    @property
    def candidate_to_finding_rate(self) -> float:
        if not self.candidates:
            return 0.0
        return self.findings / self.candidates

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.update(
            source_sink_rate=round(self.source_sink_rate, 4),
            chain_rate=round(self.chain_rate, 4),
            linked_flow_rate=round(self.linked_flow_rate, 4),
            tainted_graph_rate=round(self.tainted_graph_rate, 4),
            candidate_to_finding_rate=round(self.candidate_to_finding_rate, 4),
        )
        return data


@dataclass
class QualityScan:
    reports: list[ReportQuality]
    invalid_reports: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        totals = Counter()
        risk_domains: Counter[str] = Counter()
        graph_statuses: Counter[str] = Counter()
        statuses: Counter[str] = Counter()
        proof_levels: Counter[str] = Counter()
        for report in self.reports:
            for key in (
                "anchors",
                "slices",
                "candidates",
                "aggregated_candidates",
                "findings",
                "source_code_findings",
                "source_sink_complete",
                "missing_source",
                "missing_sink",
                "call_chain_ge_3",
                "linked_flow_findings",
                "unlinked_flow_findings",
                "tainted_graph_findings",
                "parameter_graph_findings",
                "unlinked_graph_findings",
                "llm_triage_accepted",
                "llm_triage_blocked",
                "weak_evidence",
                "noise_path_findings",
                "low_priority_path_findings",
                "dynamically_proven",
            ):
                totals[key] += int(getattr(report, key))
            risk_domains.update(report.risk_domains)
            graph_statuses.update(report.graph_statuses)
            statuses.update(report.verification_statuses)
            proof_levels.update(report.proof_levels)

        source_count = totals["source_code_findings"]
        candidate_count = totals["candidates"]
        summary = dict(totals)
        summary.update(
            report_count=len(self.reports),
            invalid_report_count=len(self.invalid_reports),
            source_sink_rate=round(totals["source_sink_complete"] / source_count, 4) if source_count else 0.0,
            chain_rate=round(totals["call_chain_ge_3"] / source_count, 4) if source_count else 0.0,
            linked_flow_rate=round(totals["linked_flow_findings"] / source_count, 4) if source_count else 0.0,
            tainted_graph_rate=round(totals["tainted_graph_findings"] / source_count, 4) if source_count else 0.0,
            candidate_to_finding_rate=round(totals["findings"] / candidate_count, 4) if candidate_count else 0.0,
            risk_domains=dict(risk_domains.most_common()),
            graph_statuses=dict(graph_statuses.most_common()),
            verification_statuses=dict(statuses.most_common()),
            proof_levels=dict(proof_levels.most_common()),
        )
        return {
            "summary": summary,
            "reports": [report.to_dict() for report in self.reports],
            "invalid_reports": self.invalid_reports,
        }

    def to_markdown(self) -> str:
        data = self.to_dict()
        summary = data["summary"]
        lines = [
            "# 漏洞挖掘质量基线",
            "",
            f"- 报告数：{summary['report_count']}",
            f"- Finding 数：{summary.get('findings', 0)}",
            f"- Source Code Finding 数：{summary.get('source_code_findings', 0)}",
            f"- Source/Sink 完整率：{summary['source_sink_rate']:.1%}",
            f"- 变量流识别率：{summary['linked_flow_rate']:.1%}",
            f"- EvidenceGraph 事实 taint 连通率：{summary['tainted_graph_rate']:.1%}",
            f"- 三节点以上证据链比例：{summary['chain_rate']:.1%}",
            f"- 动态证据命中数：{summary.get('dynamically_proven', 0)}",
            "",
            "| 项目 | 时间 | 候选 | Finding | Source Code | Source/Sink | 变量流 | 事实图 | 链路>=3 | 动态证据 |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
        for report in self.reports:
            lines.append(
                "| {target} | {created} | {candidates} | {findings} | {source_code} | "
                "{source_sink:.1%} | {linked_flow:.1%} | {tainted_graph:.1%} | {chain:.1%} | {dynamic} |".format(
                    target=_escape_markdown(report.target),
                    created=report.created_at or "unknown",
                    candidates=report.candidates,
                    findings=report.findings,
                    source_code=report.source_code_findings,
                    source_sink=report.source_sink_rate,
                    linked_flow=report.linked_flow_rate,
                    tainted_graph=report.tainted_graph_rate,
                    chain=report.chain_rate,
                    dynamic=report.dynamically_proven,
                )
            )
        if self.invalid_reports:
            lines.extend(["", "## 无法读取的报告", ""])
            for item in self.invalid_reports:
                lines.append(f"- `{item['path']}`：{item['error']}")
        return "\n".join(lines).rstrip() + "\n"


def analyze_report(path: Path, data: dict[str, Any] | None = None) -> ReportQuality:
    raw = data if data is not None else json.loads(path.read_text(encoding="utf-8"))
    findings = _dict_list(raw.get("findings"))
    verifications = _dict_list(raw.get("verification_results"))
    risk_domains: Counter[str] = Counter()
    graph_statuses: Counter[str] = Counter()
    statuses: Counter[str] = Counter()
    proof_levels: Counter[str] = Counter()
    source_code_findings = 0
    source_sink_complete = 0
    missing_source = 0
    missing_sink = 0
    call_chain_ge_3 = 0
    linked_flow_findings = 0
    unlinked_flow_findings = 0
    tainted_graph_findings = 0
    parameter_graph_findings = 0
    unlinked_graph_findings = 0
    llm_triage_accepted = 0
    llm_triage_blocked = 0
    weak_evidence = 0
    noise_path_findings = 0
    low_priority_path_findings = 0
    path_policy = PathPolicy()

    for finding in findings:
        domain = str(finding.get("risk_domain") or "unknown")
        risk_domains[domain] += 1
        if domain != "source_code":
            continue
        source_code_findings += 1
        path_decision = path_policy.classify(str(finding.get("file_path") or ""))
        if path_decision.action == "exclude":
            noise_path_findings += 1
        elif path_decision.action == "deprioritize":
            low_priority_path_findings += 1
        source = _meaningful_endpoint(finding.get("source"), source=True)
        sink = _meaningful_endpoint(finding.get("sink"), source=False)
        if source and sink:
            source_sink_complete += 1
        if not source:
            missing_source += 1
        if not sink:
            missing_sink += 1
        chain = _sequence(finding.get("exploit_chain")) or _sequence(finding.get("call_chain"))
        if len(chain) >= 3:
            call_chain_ge_3 += 1

        graph_status = _evidence_graph_status(finding)
        if graph_status:
            graph_statuses[graph_status] += 1
            if graph_status in FACT_GRAPH_STATUSES:
                tainted_graph_findings += 1
            elif graph_status in PARAMETER_GRAPH_STATUSES:
                parameter_graph_findings += 1
            elif graph_status in UNLINKED_GRAPH_STATUSES:
                unlinked_graph_findings += 1

        flow_status = str(finding.get("flow_status") or "").lower()
        if graph_status:
            if graph_status in FACT_GRAPH_STATUSES:
                linked_flow_findings += 1
            elif graph_status in PARAMETER_GRAPH_STATUSES or graph_status in UNLINKED_GRAPH_STATUSES or _sequence(finding.get("flow_gaps")):
                unlinked_flow_findings += 1
        elif flow_status in LINKED_FLOW_STATUSES:
            linked_flow_findings += 1
        elif flow_status == "sink_unlinked" or _sequence(finding.get("flow_gaps")):
            unlinked_flow_findings += 1

        triage_verdict = str(finding.get("triage_verdict") or "").lower()
        if triage_verdict == "accept":
            llm_triage_accepted += 1
        elif triage_verdict in {"reject", "needs_more_context"}:
            llm_triage_blocked += 1
        if str(finding.get("evidence_strength") or "weak").lower() == "weak":
            weak_evidence += 1

    dynamically_proven = 0
    for verification in verifications:
        status = str(verification.get("status") or "unknown")
        proof = str(verification.get("proof_level") or "none")
        statuses[status] += 1
        proof_levels[proof] += 1
        if status in {"verified", "harness_reproduced", "partial_dynamic_proof"} or proof in {
            "full_runtime",
            "native_cli",
            "generated_harness",
            "micro_proof",
        }:
            dynamically_proven += 1

    input_source = raw.get("input_source") if isinstance(raw.get("input_source"), dict) else {}
    target = _target_name(str(input_source.get("original") or raw.get("target") or path.parent.name))
    return ReportQuality(
        report_id=path.parent.name,
        target=target,
        created_at=str(raw.get("created_at") or ""),
        anchors=len(_sequence(raw.get("dangerous_functions"))),
        slices=len(_sequence(raw.get("program_slices"))),
        candidates=len(_sequence(raw.get("candidates"))),
        aggregated_candidates=len(_sequence(raw.get("aggregated_candidates"))),
        findings=len(findings),
        source_code_findings=source_code_findings,
        source_sink_complete=source_sink_complete,
        missing_source=missing_source,
        missing_sink=missing_sink,
        call_chain_ge_3=call_chain_ge_3,
        linked_flow_findings=linked_flow_findings,
        unlinked_flow_findings=unlinked_flow_findings,
        tainted_graph_findings=tainted_graph_findings,
        parameter_graph_findings=parameter_graph_findings,
        unlinked_graph_findings=unlinked_graph_findings,
        llm_triage_accepted=llm_triage_accepted,
        llm_triage_blocked=llm_triage_blocked,
        weak_evidence=weak_evidence,
        noise_path_findings=noise_path_findings,
        low_priority_path_findings=low_priority_path_findings,
        dynamically_proven=dynamically_proven,
        risk_domains=dict(risk_domains.most_common()),
        graph_statuses=dict(graph_statuses.most_common()),
        verification_statuses=dict(statuses.most_common()),
        proof_levels=dict(proof_levels.most_common()),
    )


def scan_reports(reports_dir: Path, *, latest_only: bool = True) -> QualityScan:
    analyzed: list[tuple[ReportQuality, float]] = []
    invalid: list[dict[str, str]] = []
    for path in sorted(reports_dir.glob("*/audit-report.json")):
        try:
            report = analyze_report(path)
            analyzed.append((report, path.stat().st_mtime))
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            invalid.append({"path": str(path), "error": str(exc)})

    if latest_only:
        latest: dict[str, tuple[ReportQuality, float]] = {}
        for report, modified_at in analyzed:
            current = latest.get(report.target)
            if current is None or _report_order(report, modified_at) > _report_order(*current):
                latest[report.target] = (report, modified_at)
        analyzed = list(latest.values())

    reports = [item[0] for item in analyzed]
    reports.sort(key=lambda item: (item.target.lower(), item.created_at, item.report_id))
    return QualityScan(reports=reports, invalid_reports=invalid)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze vulnerability-mining quality across audit reports.")
    parser.add_argument("reports_dir", nargs="?", type=Path, default=Path("reports"))
    parser.add_argument("--all", action="store_true", help="Include every report instead of only the latest per target.")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    scan = scan_reports(args.reports_dir, latest_only=not args.all)
    output = scan.to_markdown() if args.format == "markdown" else json.dumps(scan.to_dict(), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
    else:
        print(output, end="")
    return 0


def _dict_list(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _sequence(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _meaningful_endpoint(value: Any, *, source: bool) -> bool:
    text = str(value or "").strip().lower()
    placeholders = {"unknown", "n/a", "none", "tool_verified", "untrusted input", "security sink"}
    if not text or text in placeholders:
        return False
    if source and (text.startswith("tool_verified(") or text.startswith("tool:") or text == "user input"):
        return False
    return True


def _evidence_graph_status(finding: dict[str, Any]) -> str:
    status = str(finding.get("slice_status") or "").strip().lower()
    if status:
        return status
    graph = finding.get("evidence_graph")
    if isinstance(graph, dict):
        return str(graph.get("status") or "").strip().lower()
    return ""


def _target_name(value: str) -> str:
    normalized = value.replace("\\", "/").rstrip("/")
    parsed = urlparse(normalized)
    path = parsed.path if parsed.scheme and parsed.netloc else normalized
    parts = [part for part in path.split("/") if part]
    if "tree" in parts:
        parts = parts[: parts.index("tree")]
    if len(parts) >= 2 and parsed.netloc:
        return "/".join(parts[-2:]).removesuffix(".git")
    return (parts[-1] if parts else normalized).removesuffix(".git") or "unknown"


def _report_order(report: ReportQuality, modified_at: float) -> tuple[float, float]:
    try:
        created = datetime.fromisoformat(report.created_at.replace("Z", "+00:00")).timestamp()
    except (ValueError, OSError):
        created = 0.0
    return created, modified_at


def _escape_markdown(value: str) -> str:
    return value.replace("|", "\\|")


if __name__ == "__main__":
    raise SystemExit(main())
