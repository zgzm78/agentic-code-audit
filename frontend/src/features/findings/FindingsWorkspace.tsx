import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { AlertTriangle, Check, ChevronRight, CircleDot, ExternalLink, FileCode2, Filter, GitBranch, Search, ShieldCheck } from "lucide-react";
import type { AuditActions, AuditData } from "../../App";
import type { Finding } from "../../components/types";
import EvidenceGraph from "./EvidenceGraph";

export default function FindingsWorkspace({ data, actions }: { data: AuditData; actions: AuditActions }) {
  const [params, setParams] = useSearchParams();
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [selected, setSelected] = useState<Finding | null>(null);
  const [nodeDetail, setNodeDetail] = useState<any>(null);
  const [graphMode, setGraphMode] = useState<"evidence" | "calls">("evidence");
  const filtered = useMemo(() => data.findings.filter((f) => (severity === "all" || f.severity === severity) && (!query || `${f.title} ${f.cwe} ${f.file_path}`.toLowerCase().includes(query.toLowerCase()))), [data.findings, query, severity]);
  const activeGraph = graphMode === "calls" ? selected?.call_graph : selected?.chain_graph;
  const activeGraphTitle = graphMode === "calls" ? "函数调用连通图" : "攻击证据链";

  useEffect(() => {
    const id = params.get("finding");
    const target = data.findings.find((f) => f.id === id) || data.findings[0];
    if (target && target.id !== selected?.id) actions.loadFinding(target).then(setSelected).catch(() => setSelected(target));
  }, [data.findings, params, actions, selected?.id]);

  const choose = (finding: Finding) => { setParams({ finding: finding.id }); setNodeDetail(null); };
  return <div className="findings-view">
    <aside className="finding-browser">
      <div className="browser-head"><span className="eyebrow">FINDINGS</span><div><h1>漏洞调查</h1><strong>{data.findings.length}</strong></div></div>
      <div className="finding-search"><Search size={15} /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="搜索漏洞、CWE、文件" /></div>
      <div className="severity-filter"><Filter size={13} />{["all", "critical", "high", "medium", "low"].map((level) => <button className={severity === level ? "active" : ""} onClick={() => setSeverity(level)} key={level}>{level === "all" ? "全部" : level}</button>)}</div>
      <div className="finding-results">{filtered.map((finding) => <button key={finding.id} className={`finding-result ${selected?.id === finding.id ? "active" : ""}`} onClick={() => choose(finding)}><span className={`severity-bar ${finding.severity}`} /><div className="finding-result-top"><em>{finding.severity}</em><span>{finding.cwe || "CWE —"}</span></div><strong>{finding.title}</strong><small><FileCode2 size={11} />{finding.file_path}:{finding.line_start || "-"}</small><div className="proof-line"><i className={proofClass(finding)} /><span>{proofLabel(finding)}</span><b>{Math.round((finding.confidence || 0) * 100)}%</b></div></button>)}{!filtered.length && <div className="browser-empty">没有匹配的漏洞</div>}</div>
    </aside>

    <main className="investigation-stage">
      <div className="investigation-head">{selected ? <><div><span className={`severity-pill ${selected.severity}`}>{selected.severity}</span><span>{selected.vulnerability_type}</span><span>{selected.cwe || "CWE 未映射"}</span></div><h2>{selected.title}</h2><p>{selected.chinese_summary || selected.description}</p></> : <><div><span>未选择发现</span></div><h2>选择一个漏洞开始调查</h2></>}</div>
      <div className="graph-toolbar"><div><GitBranch size={15} /><strong>{activeGraphTitle}</strong><span>{activeGraph?.nodes?.length || 0} 节点</span></div><div className="graph-switch"><button className={graphMode === "evidence" ? "active" : ""} onClick={() => { setGraphMode("evidence"); setNodeDetail(null); }}>证据链</button><button className={graphMode === "calls" ? "active" : ""} onClick={() => { setGraphMode("calls"); setNodeDetail(null); }}>调用图</button></div><div className="graph-legend"><span><i className="source" />Source</span><span><i className="path" />Path</span><span><i className="sink" />Sink</span></div></div>
      <EvidenceGraph graph={activeGraph} onNodeSelect={setNodeDetail} />
      {nodeDetail && <div className="node-inspector"><button onClick={() => setNodeDetail(null)}>×</button><small>{nodeDetail.type}</small><strong>{nodeDetail.label}</strong><span>{nodeDetail.file_path}:{nodeDetail.line || ""}</span><p>{nodeDetail.detail || "该节点参与当前漏洞的攻击路径。"}</p></div>}
    </main>

    <aside className="evidence-inspector"><div className="inspector-head"><span className="eyebrow">EVIDENCE</span><h2>证据检查器</h2></div>{selected ? <EvidenceInspector finding={selected} /> : <div className="inspector-empty"><ShieldCheck size={28} /><p>选择漏洞后查看证明等级、触发条件与验证产物。</p></div>}</aside>
  </div>;
}

function EvidenceInspector({ finding }: { finding: Finding }) {
  const verification = finding.verification;
  const stages = [{ label: "静态命中", state: finding.evidence?.length ? "done" : "pending", detail: `${finding.evidence?.length || 0} 条代码证据` }, { label: "路径可达", state: finding.reachability === "reachable" ? "done" : "partial", detail: finding.reachability || "待判定" }, { label: "动态验证", state: verification?.dynamic_attempted ? "done" : "pending", detail: verification?.dynamic_attempted ? "已执行验证" : "未执行" }, { label: "Checker 判定", state: ["verified", "exploitable"].includes(String(verification?.status)) ? "done" : "partial", detail: String(verification?.status || "not verified") }];
  return <div className="inspector-content"><div className="proof-score"><div><CircleDot size={18} /><span>证明等级</span></div><strong>{String(verification?.proof_level || finding.evidence_strength || "weak")}</strong><small>置信度 {Math.round((finding.confidence || 0) * 100)}%</small></div>
    <div className="proof-stages">{stages.map((stage, i) => <div className={`proof-stage ${stage.state}`} key={stage.label}><span>{stage.state === "done" ? <Check size={13} /> : i + 1}</span><div><strong>{stage.label}</strong><small>{stage.detail}</small></div></div>)}</div>
    <InspectorSection title="触发条件" icon={<AlertTriangle size={14} />} items={finding.trigger_conditions || []} />
    <InspectorSection title="静态证据" icon={<FileCode2 size={14} />} items={finding.evidence || []} />
    <div className="inspector-section"><h3><ShieldCheck size={14} />修复建议</h3><p>{finding.recommendation || finding.verification_reason || "在危险调用前增加输入约束，并为攻击路径添加回归测试。"}</p></div>
    {(verification?.artifact_records || []).length > 0 && <div className="inspector-section"><h3><ExternalLink size={14} />验证产物</h3>{verification!.artifact_records!.map((a) => <a key={a.id} href={`/api/artifacts/${a.id}`} target="_blank">{a.kind || "artifact"}<ChevronRight size={13} /></a>)}</div>}
  </div>;
}
function InspectorSection({ title, icon, items }: any) { if (!items.length) return null; return <div className="inspector-section"><h3>{icon}{title}</h3><ul>{items.slice(0, 5).map((item: string, i: number) => <li key={i}>{item}</li>)}</ul></div>; }
function proofClass(f: Finding) { return ["verified", "exploitable"].includes(String(f.verification?.status)) ? "verified" : f.verification?.dynamic_attempted ? "partial" : "static"; }
function proofLabel(f: Finding) { return ["verified", "exploitable"].includes(String(f.verification?.status)) ? "已验证" : f.verification?.dynamic_attempted ? "部分验证" : "静态证据"; }
