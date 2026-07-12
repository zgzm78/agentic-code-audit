import ReactEChartsCore from "echarts-for-react/lib/core";
import * as echarts from "echarts/core";
import { PieChart } from "echarts/charts";
import { TooltipComponent } from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import { AlertTriangle, ArrowUpRight, CheckCircle2, CircleDashed, Clock3, Crosshair, FileCode2, Layers3, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";
import type { AuditData } from "../../App";
import type { Finding } from "../../components/types";

echarts.use([PieChart, TooltipComponent, CanvasRenderer]);

export default function Overview({ data }: { data: AuditData }) {
  const severity = count(data.findings, (f) => f.severity || "unknown");
  const verified = data.findings.filter((f) => ["verified", "exploitable"].includes(String(f.verification?.status))).length;
  const highRisk = (severity.critical || 0) + (severity.high || 0);
  const funnel = getFunnel(data);
  const recent = [...data.findings].sort((a, b) => score(b) - score(a)).slice(0, 5);

  return <div className="view overview-view">
    <section className="view-intro">
      <div><span className="eyebrow">AUDIT CONTROL</span><h1>安全态势总览</h1><p>{data.task ? `${data.task.target} 的实时调查摘要` : "选择或创建任务，开始构建代码安全证据。"}</p></div>
      <div className={`audit-state ${data.task?.status || "idle"}`}><span /><div><small>任务状态</small><strong>{statusLabel(data.task?.status)}</strong></div></div>
    </section>

    <section className="signal-strip">
      <Signal icon={<AlertTriangle />} label="高危暴露" value={highRisk} detail={`${severity.critical || 0} 个严重风险`} tone="danger" />
      <Signal icon={<Crosshair />} label="已确认漏洞" value={verified} detail={`${data.findings.length ? Math.round(verified / data.findings.length * 100) : 0}% 验证率`} tone="verified" />
      <Signal icon={<Layers3 />} label="候选收敛" value={funnel[3]} detail={`来自 ${funnel[0]} 个锚点`} />
      <Signal icon={<Clock3 />} label="事件脉冲" value={data.events.length} detail={data.events.length ? "审计轨迹已记录" : "等待审计启动"} />
    </section>

    <section className="overview-grid">
      <div className="surface risk-surface">
        <SectionTitle eyebrow="RISK DISTRIBUTION" title="风险构成" action={<Link to="/findings">进入调查 <ArrowUpRight size={14} /></Link>} />
        <div className="risk-chart-wrap"><ReactEChartsCore className="risk-chart" echarts={echarts} option={riskOption(severity)} notMerge lazyUpdate style={{ height: "100%", minHeight: 238, width: "100%" }} />
          <div className="risk-legend">{["critical", "high", "medium", "low"].map((key) => <div key={key}><i className={key} /><span>{key}</span><strong>{severity[key] || 0}</strong></div>)}</div>
        </div>
      </div>
      <div className="surface funnel-surface">
        <SectionTitle eyebrow="EVIDENCE PIPELINE" title="证据收敛路径" />
        <EvidenceFunnel values={funnel} />
        <p className="surface-note">每一步都保留可追溯引用，确保最终结论可以回到原始工具输出与代码位置。</p>
      </div>
      <div className="surface activity-surface">
        <SectionTitle eyebrow="LIVE PIPELINE" title="Agent 执行轨道" action={<Link to="/live">查看实时流 <ArrowUpRight size={14} /></Link>} />
        <AgentTrack events={data.events} taskStatus={data.task?.status} />
      </div>
      <div className="surface findings-surface">
        <SectionTitle eyebrow="PRIORITY QUEUE" title="优先处置" action={<Link to="/findings">全部发现 <ArrowUpRight size={14} /></Link>} />
        <div className="priority-list">{recent.map((finding, index) => <Link to={`/findings?finding=${finding.id}`} key={finding.id} className="priority-row"><span className={`severity-index ${finding.severity}`}>{String(index + 1).padStart(2, "0")}</span><div><strong>{finding.title}</strong><small><FileCode2 size={12} />{finding.file_path}:{finding.line_start || "-"}</small></div><div className="priority-proof"><em>{finding.cwe || "CWE —"}</em><span>{String(finding.verification?.status || "待验证")}</span></div></Link>)}{!recent.length && <Empty />}</div>
      </div>
    </section>
  </div>;
}

function Signal({ icon, label, value, detail, tone = "" }: any) { return <div className={`signal ${tone}`}><span className="signal-icon">{icon}</span><div><small>{label}</small><strong>{value}</strong><p>{detail}</p></div></div>; }
function SectionTitle({ eyebrow, title, action }: any) { return <div className="section-title"><div><small>{eyebrow}</small><h2>{title}</h2></div>{action}</div>; }
function Empty() { return <div className="content-empty"><ShieldCheck size={26} /><span>暂无风险发现</span><small>审计结果会在这里形成处置队列</small></div>; }

function EvidenceFunnel({ values }: { values: number[] }) {
  const labels = ["Anchors", "Slices", "Candidates", "Findings", "Verified"];
  const normalized = values.map((value) => Math.max(0, Number(value) || 0));
  const maximum = Math.max(1, ...normalized);
  return <div className="evidence-funnel">{labels.map((label, index) => {
    const value = normalized[index];
    const conversion = index < labels.length - 1 && value ? Math.round(normalized[index + 1] / value * 100) : 0;
    return <div className="funnel-step" key={label}><div className="funnel-track"><span style={{ width: `${value / maximum * 100}%` }} /></div><div><span>{label}</span><strong>{value}</strong></div>{index < labels.length - 1 && <small>{conversion}%</small>}</div>;
  })}</div>;
}

function AgentTrack({ events, taskStatus }: { events: any[]; taskStatus?: string }) {
  const agents = [{ id: "InputAgent", label: "输入解析" }, { id: "ReconAgent", label: "项目侦察" }, { id: "VulnerabilityMiningAgent", label: "漏洞挖掘" }, { id: "VerificationAgent", label: "证据验证" }, { id: "ReportAgent", label: "报告生成" }];
  const latest = [...events].reverse().find((e) => agents.some((a) => a.id === e.agent));
  const activeIndex = taskStatus === "completed" ? agents.length : Math.max(0, agents.findIndex((a) => a.id === latest?.agent));
  return <div className="agent-track">{agents.map((agent, index) => { const done = index < activeIndex || taskStatus === "completed"; const active = index === activeIndex && taskStatus === "running"; return <div className={`agent-step ${done ? "done" : ""} ${active ? "active" : ""}`} key={agent.id}><div className="agent-rail"><span>{done ? <CheckCircle2 size={17} /> : active ? <span className="pulse-core" /> : <CircleDashed size={17} />}</span>{index < agents.length - 1 && <i />}</div><div><strong>{agent.label}</strong><small>{done ? "已完成" : active ? latest?.message || "执行中" : "等待中"}</small></div></div>; })}</div>;
}

function count(items: Finding[], key: (f: Finding) => string) { return items.reduce<Record<string, number>>((acc, item) => { const k = key(item).toLowerCase(); acc[k] = (acc[k] || 0) + 1; return acc; }, {}); }
function score(f: Finding) { return ({ critical: 4, high: 3, medium: 2, low: 1 } as any)[f.severity] || 0; }
function getFunnel(data: AuditData) { const d = data.debug || {}; const sum = (v?: Record<string, number>) => Object.values(v || {}).reduce((a, b) => a + Number(b), 0); return [sum(d.tool_anchor_count_by_tool), sum(d.slice_count_by_language), Number(d.candidate_validity_breakdown?.total || d.aggregation_input_count || 0), data.findings.length, data.findings.filter((f) => ["verified", "exploitable"].includes(String(f.verification?.status))).length]; }
function statusLabel(status?: string) { return ({ running: "审计进行中", completed: "调查已完成", failed: "执行失败", queued: "等待启动", cancelled: "已停止" } as any)[status || ""] || "未选择任务"; }
function riskOption(counts: Record<string, number>) { const data = [{ name: "严重", value: counts.critical || 0, itemStyle: { color: "#ef5b5b" } }, { name: "高危", value: counts.high || 0, itemStyle: { color: "#f39b55" } }, { name: "中危", value: counts.medium || 0, itemStyle: { color: "#e2c15c" } }, { name: "低危", value: counts.low || 0, itemStyle: { color: "#52b8a5" } }]; if (!data.some((d) => d.value)) data.push({ name: "暂无", value: 1, itemStyle: { color: "#25303a" } }); return { animationDuration: 700, animationEasing: "cubicOut", tooltip: { trigger: "item", backgroundColor: "#09131b", borderColor: "#31505f", textStyle: { color: "#dcecf2" } }, series: [{ type: "pie", radius: ["58%", "82%"], center: ["50%", "50%"], avoidLabelOverlap: false, label: { show: false }, emphasis: { scaleSize: 4 }, data }] }; }
