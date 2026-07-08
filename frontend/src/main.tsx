import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  Boxes,
  Bug,
  Download,
  FileText,
  GitBranch,
  History,
  Loader2,
  Play,
  Radio,
  ShieldAlert,
  Square,
  Terminal,
} from "lucide-react";
import "./styles.css";

type Task = {
  id: string;
  target: string;
  status: string;
  model: string;
  created_at: string;
  started_at?: string;
  finished_at?: string;
  markdown_report?: string;
  findings?: Finding[];
  error?: string;
};

type EventItem = {
  sequence: number;
  agent: string;
  event_type: string;
  message: string;
  metadata: Record<string, unknown>;
  created_at: string;
};

type Finding = {
  id: string;
  title: string;
  severity: string;
  vulnerability_type: string;
  file_path: string;
  line_start?: number;
  description: string;
  chinese_summary?: string;
  chain_graph?: ChainGraph;
  evidence?: string[];
  trigger_conditions?: string[];
  verification?: VerificationInfo | null;
};

type VerificationInfo = {
  status?: string;
  verification_mode?: string;
  checker_status?: string;
  reproduction?: string;
  evidence?: string[];
  [key: string]: unknown;
};

type ChainGraph = {
  nodes: Array<{ id: string; label: string; type: string; file_path?: string; line?: number; detail?: string }>;
  edges: Array<{ source: string; target: string; type: string; label?: string }>;
};

const API = import.meta.env.VITE_API_BASE_URL || "";
const TERMINAL_STATUSES = new Set(["completed", "failed", "cancelled"]);
const TOP_LEVEL_AGENTS = [
  "InputAgent",
  "ReconAgent",
  "ToolAgent",
  "VulnerabilityMiningAgent",
  "VerificationAgent",
  "ReportAgent",
];
const MINING_STEPS = [
  ["DangerousFunctionLocator", "危险函数定位"],
  ["SliceAnalyzer", "切片分析"],
  ["CandidateGenerator", "候选生成"],
  ["ClueAggregator", "线索汇聚"],
  ["VulnerabilityClassifier", "类型判定"],
];
const PHASE_ORDER = [
  "InputAgent",
  "ReconAgent",
  "ToolAgent",
  "DangerousFunctionLocator",
  "SliceAnalyzer",
  "CandidateGenerator",
  "ClueAggregator",
  "VulnerabilityClassifier",
  "VerificationAgent",
  "ReportAgent",
];

function App() {
  const [health, setHealth] = useState<Record<string, unknown> | null>(null);
  const [tasks, setTasks] = useState<Task[]>([]);
  const [task, setTask] = useState<Task | null>(null);
  const [events, setEvents] = useState<EventItem[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [report, setReport] = useState("");
  const [target, setTarget] = useState("https://github.com/Exiv2/exiv2.git");
  const [runtimeUrl, setRuntimeUrl] = useState("");
  const [statusText, setStatusText] = useState("创建任务后会进入历史记录，需手动点击开始。");
  const [lastEventAt, setLastEventAt] = useState<number | null>(null);
  const [clock, setClock] = useState(Date.now());

  useEffect(() => {
    fetchJson("/api/health").then(setHealth).catch(() => setHealth(null));
    refreshTasks();
  }, []);

  useEffect(() => {
    const timer = window.setInterval(() => setClock(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    if (!task?.id || task.status !== "running") return;
    const stream = new EventSource(`${API}/api/tasks/${task.id}/events`);
    const append = (message: MessageEvent) => {
      const item = JSON.parse(message.data);
      if (item.sequence) {
        setEvents((prev) => (prev.some((event) => event.sequence === item.sequence) ? prev : [...prev, item]));
        setLastEventAt(Date.now());
      }
      loadTask(task.id);
      const terminalStatus = item.status && TERMINAL_STATUSES.has(String(item.status));
      const terminalEvent = ["task_completed", "task_cancelled", "error"].includes(String(item.event_type || ""));
      if (terminalStatus || terminalEvent) stream.close();
    };
    stream.onmessage = append;
    [
      "task_created",
      "task_started",
      "task_cancelled",
      "stage_start",
      "stage_done",
      "tool_start",
      "tool_end",
      "finding",
      "verification",
      "report",
      "error",
      "task_completed",
      "heartbeat",
    ].forEach((name) => stream.addEventListener(name, append));
    return () => stream.close();
  }, [task?.id, task?.status]);

  async function refreshTasks() {
    const data = await fetchJson("/api/tasks");
    setTasks(data);
    return data;
  }

  async function loadTask(taskId: string) {
    const data = await fetchJson(`/api/tasks/${taskId}`);
    setTask(data);
    setFindings(data.findings || []);
    if (data.status === "completed") {
      const text = await fetch(`${API}/api/tasks/${taskId}/report.md`).then((r) => (r.ok ? r.text() : ""));
      setReport(text);
    } else {
      setReport("");
    }
  }

  async function loadTaskWithEvents(taskId: string) {
    const [detail, eventData] = await Promise.all([
      fetchJson(`/api/tasks/${taskId}`),
      fetchJson(`/api/tasks/${taskId}/events/history`).catch(() => []),
    ]);
    setTask(detail);
    setFindings(detail.findings || []);
    setEvents(eventData);
    setSelectedFinding(null);
    setLastEventAt(eventData.length ? Date.now() : null);
    if (detail.status === "completed") {
      const text = await fetch(`${API}/api/tasks/${taskId}/report.md`).then((r) => (r.ok ? r.text() : ""));
      setReport(text);
    } else {
      setReport("");
    }
  }

  async function createTask(event: React.FormEvent) {
    event.preventDefault();
    setStatusText("正在创建任务");
    const response = await fetch(`${API}/api/tasks`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, mode: "full", runtime_url: runtimeUrl }),
    });
    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: "创建失败" }));
      setStatusText(String(error.detail || "创建失败"));
      return;
    }
    const data = await response.json();
    setStatusText("任务已创建，点击开始审计后才会运行。");
    await refreshTasks();
    await loadTaskWithEvents(data.task_id);
  }

  async function startSelectedTask() {
    if (!task) return;
    setStatusText("正在启动审计任务");
    const response = await fetch(`${API}/api/tasks/${task.id}/start`, { method: "POST" });
    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: "启动失败" }));
      setStatusText(String(error.detail || "启动失败"));
      return;
    }
    setEvents([]);
    setFindings([]);
    setReport("");
    setLastEventAt(Date.now());
    await refreshTasks();
    await loadTask(task.id);
  }

  async function stopSelectedTask() {
    if (!task) return;
    setStatusText("正在停止任务");
    await fetch(`${API}/api/tasks/${task.id}/cancel`, { method: "POST" });
    await refreshTasks();
    await loadTask(task.id);
    setStatusText("任务已停止");
  }

  async function openFinding(finding: Finding) {
    if (!task) return;
    const detail = await fetchJson(`/api/tasks/${task.id}/findings/${finding.id}`);
    setSelectedFinding(detail);
  }

  const progress = useMemo(() => {
    if (!task) return { percent: 0, label: "未选择任务", current: "Idle" };
    if (task.status === "completed") return { percent: 100, label: "已完成", current: "ReportAgent" };
    if (task.status === "cancelled") return { percent: 0, label: "已停止", current: "Stopped" };
    if (task.status === "failed") return { percent: 0, label: "失败", current: "Failed" };
    if (task.status === "queued") return { percent: 0, label: "等待开始", current: "Queued" };
    const latest = [...events].reverse().find((event) => PHASE_ORDER.includes(event.agent));
    const current = latest?.agent || "Orchestrator";
    const index = Math.max(0, PHASE_ORDER.indexOf(current));
    const percent = Math.max(5, Math.round(((index + 1) / PHASE_ORDER.length) * 100));
    return { percent, label: latest?.message || "运行中", current };
  }, [task, events]);

  const liveHint = useMemo(() => {
    if (task?.status !== "running") return "";
    if (!lastEventAt) return "等待第一条事件";
    const seconds = Math.floor((clock - lastEventAt) / 1000);
    if (seconds < 20) return "实时事件正常";
    return `已有 ${seconds}s 没有新事件，可能正在执行长耗时工具`;
  }, [task?.status, lastEventAt, events.length, clock]);

  const stats = [
    ["任务状态", task?.status || "none"],
    ["当前阶段", progress.current],
    ["模型", String(health?.model || "unknown")],
    ["漏洞数", String(findings.length)],
    ["事件数", String(events.length)],
    ["DeepSeek", health?.deepseek_configured ? "已配置" : "未配置"],
  ];

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <ShieldAlert size={24} />
          <div>
            <strong>Agentic Code Audit</strong>
            <span>DeepAudit 风格源码审计平台</span>
          </div>
        </div>

        <form onSubmit={createTask} className="task-form">
          <label>目标仓库 / 本地路径</label>
          <input value={target} onChange={(e) => setTarget(e.target.value)} />
          <label>Runtime URL</label>
          <input value={runtimeUrl} onChange={(e) => setRuntimeUrl(e.target.value)} placeholder="http://127.0.0.1:5000" />
          <div className="policy"><Terminal size={14} /> C/C++ 构建由系统自动决策</div>
          <button className="primary" type="submit"><Boxes size={16} />创建任务</button>
          <p className="status">{statusText}</p>
        </form>

        <div className="history-title"><History size={15} />历史任务</div>
        <div className="task-list">
          {tasks.map((item) => (
            <button key={item.id} onClick={() => loadTaskWithEvents(item.id)} className={task?.id === item.id ? "active task" : "task"}>
              <span>{item.status}</span>
              <strong>{item.target}</strong>
              <small>{new Date(item.created_at).toLocaleString()}</small>
            </button>
          ))}
        </div>
      </aside>

      <main className="workspace">
        <header className="top">
          <div>
            <h1>源码审计任务台</h1>
            <p>{task?.target || "从历史任务中选择，或创建一个新任务。"}</p>
          </div>
          <div className="actions">
            {task && task.status !== "running" && task.status !== "completed" && (
              <button className="primary" onClick={startSelectedTask}><Play size={16} />开始审计</button>
            )}
            {task?.status === "running" && (
              <button className="danger" onClick={stopSelectedTask}><Square size={15} />停止</button>
            )}
            <a className="download" href={task ? `${API}/api/tasks/${task.id}/report.md` : "#"} target="_blank" rel="noreferrer">
              <Download size={16} />报告
            </a>
          </div>
        </header>

        <section className="progress-panel">
          <div className="progress-head">
            <div>
              <strong>{progress.label}</strong>
              <span>{liveHint}</span>
            </div>
            {task?.status === "running" && <Loader2 className="spin" size={18} />}
          </div>
          <div className="progress-track"><div style={{ width: `${progress.percent}%` }} /></div>
        </section>

        <section className="stats">{stats.map(([label, value]) => <div className="stat" key={label}><span>{label}</span><strong>{value}</strong></div>)}</section>

        <section className="grid">
          <Panel title="Agent 架构" icon={<GitBranch size={18} />}>
            {TOP_LEVEL_AGENTS.map((name) => (
              <div className="agent-node" key={name}>
                <Boxes size={15} />{name}
                {name === "VulnerabilityMiningAgent" && (
                  <div className="substeps">
                    {MINING_STEPS.map(([id, label]) => <span key={id}>{label}</span>)}
                  </div>
                )}
              </div>
            ))}
          </Panel>

          <Panel title="实时事件流" icon={<Radio size={18} />}>
            <div className="log-list">
              {events.length === 0 && <div className="empty">暂无事件。创建任务后点击开始审计。</div>}
              {events.map((item) => (
                <div className={`log ${item.event_type}`} key={`${item.sequence}-${item.created_at}`}>
                  <span>{item.sequence}</span><strong>{item.agent}</strong><p>{item.message}</p>
                </div>
              ))}
            </div>
          </Panel>

          <Panel title="漏洞列表" icon={<Bug size={18} />}>
            <div className="finding-list">
              {findings.length === 0 && <div className="empty">暂无漏洞结果。</div>}
              {findings.map((finding) => (
                <button key={finding.id} onClick={() => openFinding(finding)} className="finding">
                  <div className="finding-badges">
                    <span className={`severity ${finding.severity}`}>{finding.severity}</span>
                    <span className={`verify ${verificationStatus(finding)}`}>{verificationStatus(finding)}</span>
                  </div>
                  <strong>{finding.title}</strong>
                  <small>{finding.vulnerability_type} · {finding.file_path}:{finding.line_start || ""}</small>
                </button>
              ))}
            </div>
          </Panel>

          <Panel title="漏洞详情与触发链路" icon={<Activity size={18} />}>
            {selectedFinding ? (
              <div className="detail">
                <h2>{selectedFinding.title}</h2>
                <div className="detail-badges">
                  <span className={`severity ${selectedFinding.severity}`}>{selectedFinding.severity}</span>
                  <span className={`verify ${verificationStatus(selectedFinding)}`}>{verificationStatus(selectedFinding)}</span>
                  <span className="mode">{selectedFinding.verification?.verification_mode || "not_verified"}</span>
                </div>
                <p>{selectedFinding.chinese_summary || selectedFinding.description}</p>
                <ChainGraphView graph={selectedFinding.chain_graph} />
                <h3>触发条件</h3>
                <ul>{(selectedFinding.trigger_conditions || []).map((item) => <li key={item}>{item}</li>)}</ul>
                <h3>验证证据</h3>
                <pre>{JSON.stringify(selectedFinding.verification || {}, null, 2)}</pre>
              </div>
            ) : <div className="empty">选择一个漏洞查看链路图和验证证据。</div>}
          </Panel>
        </section>

        <Panel title="报告预览" icon={<FileText size={18} />}>
          <pre className="report">{report || "任务完成后显示报告。"}</pre>
        </Panel>
      </main>
    </div>
  );
}

function ChainGraphView({ graph }: { graph?: ChainGraph }) {
  if (!graph?.nodes?.length) return <div className="empty">暂无链路图。</div>;
  return (
    <div className="chain">
      {graph.nodes.map((node, index) => (
        <React.Fragment key={node.id}>
          <div className={`chain-node ${node.type}`}>
            <strong>{node.label}</strong>
            <span>{node.type}</span>
            {node.detail && <em>{node.detail}</em>}
            <small>{node.file_path}:{node.line || ""}</small>
          </div>
          {index < graph.nodes.length - 1 && <div className="arrow">→</div>}
        </React.Fragment>
      ))}
    </div>
  );
}

function verificationStatus(finding: Finding) {
  return String(finding.verification?.status || "not_verified");
}

function Panel({ title, icon, children }: { title: string; icon: React.ReactNode; children: React.ReactNode }) {
  return <section className="panel"><div className="panel-title">{icon}<h2>{title}</h2></div>{children}</section>;
}

async function fetchJson(path: string) {
  const response = await fetch(`${API}${path}`);
  if (!response.ok) throw new Error(await response.text());
  return response.json();
}

createRoot(document.getElementById("root")!).render(<App />);
