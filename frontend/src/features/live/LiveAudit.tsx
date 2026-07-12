import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Activity, ArrowDownToLine, Box, Braces, Check, ChevronDown, CircleDot, Clock3, Cpu, FileSearch, Pause, Radio, ScanSearch, ShieldCheck, TerminalSquare } from "lucide-react";
import type { AuditData } from "../../App";

const AGENTS = [
  { id: "InputAgent", name: "Input", label: "目标解析", icon: FileSearch },
  { id: "ReconAgent", name: "Recon", label: "项目侦察", icon: ScanSearch },
  { id: "VulnerabilityMiningAgent", name: "Mining", label: "漏洞挖掘", icon: Braces },
  { id: "VerificationAgent", name: "Verify", label: "动态验证", icon: ShieldCheck },
  { id: "ReportAgent", name: "Report", label: "报告构建", icon: Box },
];

export default function LiveAudit({ data }: { data: AuditData }) {
  const [type, setType] = useState("all");
  const [follow, setFollow] = useState(true);
  const streamRef = useRef<HTMLDivElement>(null);
  const events = useMemo(() => type === "all" ? data.events : data.events.filter((event) => event.event_type.includes(type)), [data.events, type]);
  const latest = useMemo(() => {
    for (let index = data.events.length - 1; index >= 0; index -= 1) {
      if (AGENTS.some((agent) => agent.id === data.events[index].agent)) return data.events[index];
    }
    return undefined;
  }, [data.events]);
  const currentAgent = data.task?.current_agent || latest?.agent;
  const currentIndex = AGENTS.findIndex((agent) => agent.id === currentAgent);
  const active = data.task?.status === "completed" ? AGENTS.length : Math.max(0, currentIndex);
  const tools = useMemo(() => [...data.tools].sort((a, b) => Number(b.available) - Number(a.available) || a.name.localeCompare(b.name)), [data.tools]);
  const availableTools = tools.filter((tool) => tool.available).length;

  useEffect(() => {
    if (!follow) return;
    const frame = window.requestAnimationFrame(() => streamRef.current?.scrollTo({ top: streamRef.current.scrollHeight, behavior: "smooth" }));
    return () => window.cancelAnimationFrame(frame);
  }, [events.length, follow]);

  return <div className="view live-view">
    <section className="view-intro live-intro"><div><span className="eyebrow">LIVE AUDIT</span><h1>审计执行现场</h1><p>从目标解析到验证结论，观察每一步如何形成可追溯证据。</p></div><div className="live-connection"><span className={data.task?.status === "running" ? "active" : ""}><Radio size={14} /></span><div><small>EVENT SYNC</small><strong>{data.task?.status === "running" ? "实时事件与历史校准中" : "历史事件已同步"}</strong></div></div></section>
    <section className="execution-map">
      <div className="execution-line" />
      {AGENTS.map((agent, index) => {
        const done = index < active || data.task?.status === "completed";
        const running = index === active && data.task?.status === "running";
        return <div className={`execution-agent ${done ? "done" : ""} ${running ? "running" : ""}`} key={agent.id}><div className="execution-node"><agent.icon size={20} />{done && <span><Check size={11} /></span>}{running && <i />}</div><strong>{agent.name} Agent</strong><small>{agent.label}</small><em>{done ? "COMPLETED" : running ? "RUNNING" : "QUEUED"}</em></div>;
      })}
    </section>
    <section className="live-grid">
      <div className="surface event-console">
        <div className="console-head"><div><TerminalSquare size={17} /><span><small>EVENT PULSE</small><strong>证据时间束</strong></span></div><div className="console-controls"><button className={follow ? "active" : ""} onClick={() => setFollow((value) => !value)} title={follow ? "暂停自动跟随" : "跟随最新事件"}>{follow ? <Pause size={14} /> : <ArrowDownToLine size={14} />}<span>{follow ? "正在跟随" : "跟随最新"}</span></button><label><select value={type} onChange={(event) => setType(event.target.value)}><option value="all">全部事件</option><option value="tool">工具调用</option><option value="finding">漏洞发现</option><option value="verification">验证结果</option><option value="error">错误</option></select><ChevronDown size={13} /></label></div></div>
        <div className="console-body" ref={streamRef}>{events.map((event) => <article className={`console-event type-${event.event_type}`} key={`${event.sequence}-${event.created_at}`}><div className="event-time"><time>{new Date(event.created_at).toLocaleTimeString("zh-CN", { hour12: false })}</time><span>#{event.sequence}</span><i /></div><div className="event-copy"><header><strong>{event.agent}</strong><em>{event.event_type}</em></header><p>{event.message}</p></div></article>)}{!events.length && <div className="console-empty"><Activity size={23} /><span>等待审计事件</span></div>}</div>
      </div>
      <aside className="surface telemetry-panel">
        <div className="section-title"><div><small>TELEMETRY</small><h2>运行遥测</h2></div><span className={`telemetry-link ${data.task?.status === "running" ? "active" : ""}`}>{data.task?.status === "running" ? "LIVE" : "SYNCED"}</span></div>
        <div className="telemetry-summary">
          <Telemetry icon={<Clock3 />} label="事件总数" value={data.events.length} />
          <Telemetry icon={<Cpu />} label="当前 Agent" value={currentAgent?.replace("Agent", "") || "Idle"} />
          <Telemetry icon={<CircleDot />} label="可用工具" value={`${availableTools}/${tools.length}`} />
        </div>
        <div className="tool-health">
          <header><h3>工具健康度</h3><span>{availableTools} ONLINE · {tools.length - availableTools} MISSING</span></header>
          <div className="tool-health-list">{tools.map((tool) => <div className={`tool-health-row ${tool.available ? "available" : "missing"}`} key={tool.name} title={[tool.capability, tool.reason].filter(Boolean).join(" · ")}><i /><span><strong>{tool.name}</strong><small>{tool.capability}</small></span><em>{tool.execution_location || "backend"}</em></div>)}{!tools.length && <p>后端连接后显示工具状态</p>}</div>
        </div>
      </aside>
    </section>
  </div>;
}

function Telemetry({ icon, label, value }: { icon: ReactNode; label: string; value: ReactNode }) {
  return <div className="telemetry"><span>{icon}</span><div><small>{label}</small><strong>{value}</strong></div></div>;
}
