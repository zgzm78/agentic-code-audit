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
  Trash2,
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
  cwe?: string;
  confidence?: number;
  evidence_strength?: string;
  reachability?: string;
  exploitability?: string;
  should_verify?: boolean;
  file_path: string;
  line_start?: number;
  source?: string;
  sink?: string;
  function_name?: string;
  description: string;
  chinese_summary?: string;
  chain_graph?: ChainGraph;
  evidence?: string[];
  trigger_conditions?: string[];
  verification?: VerificationInfo | null;
  trace?: TraceInfo;
  artifact_refs?: string[];
  tool_run_refs?: string[];
  verification_reason?: string;
  recommendation?: string;
};

type VerificationInfo = {
  status?: string;
  runtime_type?: string;
  strategy?: string;
  verification_mode?: string;
  checker_status?: string;
  checker_summary?: string;
  reproduction?: string;
  evidence?: string[];
  environment?: Record<string, unknown>;
  environment_gaps?: string[];
  execution?: Record<string, unknown>;
  evidence_artifact_ids?: string[];
  exploit_artifact_ids?: string[];
  checker_details?: Record<string, unknown>;
  generated_artifacts?: string[];
  local_fallback?: boolean;
  [key: string]: unknown;
};

type ArtifactInfo = {
  id: string;
  kind?: string;
  path?: string;
  sha256?: string;
  size_bytes?: number;
  metadata?: Record<string, unknown>;
};

type TraceInfo = {
  candidate_id?: string;
  slice_id?: string;
  dangerous_function_id?: string;
  tool_run_refs?: string[];
  artifact_refs?: string[];
  candidate?: Record<string, unknown> | null;
  program_slice?: Record<string, unknown> | null;
  dangerous_function?: Record<string, unknown> | null;
  tool_runs?: Array<Record<string, unknown>>;
  artifacts?: ArtifactInfo[];
};

type ToolInfo = {
  name: string;
  capability: string;
  available: boolean;
  required: boolean;
  version?: string;
  reason?: string;
};

type ProfileEntry = {
  kind: string;
  file: string;
  command?: string;
  evidence?: string;
  confidence?: number;
};

type ProjectProfile = {
  languages?: Record<string, number>;
  frameworks?: string[];
  project_type?: string;
  build_entries?: ProfileEntry[];
  runtime_entries?: ProfileEntry[];
  test_entries?: ProfileEntry[];
  verification_entries?: ProfileEntry[];
  non_runnable_reasons?: string[];
  weak_verification_strategies?: string[];
  attack_surfaces?: string[];
  recommended_tools?: string[];
  recommended_tool_details?: Array<Record<string, unknown>>;
  dependency_findings_summary?: Array<Record<string, unknown>>;
  attack_priorities?: string[];
  verification_hints?: string[];
  recon_evidence_refs?: string[];
  profile_summary?: Record<string, unknown>;
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
  "VulnerabilityMiningAgent",
  "VerificationAgent",
  "ReportAgent",
];
const MINING_STEPS = [
  ["ToolModule", "工具调用"],
  ["DangerousFunctionLocator", "危险函数定位"],
  ["SliceAnalyzer", "切片分析"],
  ["CandidateGenerator", "候选生成"],
  ["ClueAggregator", "线索汇聚"],
  ["VulnerabilityClassifier", "类型判定"],
];
const PHASE_ORDER = [
  "InputAgent",
  "ReconAgent",
  "VulnerabilityMiningAgent",
  "VerificationAgent",
  "ReportAgent",
];

function App() {
  const [health, setHealth] = useState<Record<string, unknown> | null>(null);
  const [tools, setTools] = useState<ToolInfo[]>([]);
  const [profile, setProfile] = useState<ProjectProfile | null>(null);
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
    fetchJson("/api/tools").then(setTools).catch(() => setTools([]));
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
    loadProfile(taskId);
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
    loadProfile(taskId);
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

  async function deleteHistoryTask(taskId: string, taskStatus: string) {
    if (taskStatus === "running") {
      setStatusText("运行中的任务需要先停止，再删除。");
      return;
    }
    if (!window.confirm("删除该历史任务？关联报告和 artifact 记录也会被清理。")) return;
    const response = await fetch(`${API}/api/tasks/${taskId}`, { method: "DELETE" });
    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: "删除失败" }));
      setStatusText(String(error.detail || "删除失败"));
      return;
    }
    if (task?.id === taskId) {
      setTask(null);
      setEvents([]);
      setFindings([]);
      setSelectedFinding(null);
      setProfile(null);
      setReport("");
    }
    await refreshTasks();
    setStatusText("历史任务已删除");
  }

  async function openFinding(finding: Finding) {
    if (!task) return;
    const detail = await fetchJson(`/api/tasks/${task.id}/findings/${finding.id}`);
    setSelectedFinding(detail);
  }

  async function loadProfile(taskId: string) {
    const data = await fetchJson(`/api/tasks/${taskId}/profile`).catch(() => null);
    setProfile(data);
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
    ["LLM", (health?.llm_configured ?? health?.deepseek_configured) ? "已配置" : "未配置"],
    ["工具", `${tools.filter((tool) => tool.available).length}/${tools.length}`],
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
            <div key={item.id} className={task?.id === item.id ? "active task" : "task"}>
              <button className="task-main" onClick={() => loadTaskWithEvents(item.id)}>
                <span>{item.status}</span>
                <strong>{item.target}</strong>
                <small>{new Date(item.created_at).toLocaleString()}</small>
              </button>
              <button
                className="task-delete"
                title="删除历史任务"
                aria-label="删除历史任务"
                onClick={() => deleteHistoryTask(item.id, item.status)}
                disabled={item.status === "running"}
              >
                <Trash2 size={14} />
              </button>
            </div>
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
            <a className="download" href={task ? `${API}/api/tasks/${task.id}/report.json` : "#"} target="_blank" rel="noreferrer">
              <Download size={16} />JSON
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

          <Panel title="工具模块" icon={<Terminal size={18} />}>
            <ToolStatusPanel tools={tools} />
          </Panel>

          <Panel title="项目画像" icon={<FileText size={18} />}>
            <ProfileView profile={profile} />
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
                    <span className="mode">{finding.vulnerability_type}</span>
                    <span className="mode">{finding.evidence_strength || "weak"}</span>
                    <span className={`verify ${verificationStatus(finding)}`}>{verificationStatus(finding)}</span>
                  </div>
                  <strong>{finding.title}</strong>
                  <small>{finding.cwe || "CWE n/a"} · {finding.file_path}:{finding.line_start || ""}</small>
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
                  <span className="mode">{selectedFinding.evidence_strength || "weak"}</span>
                </div>
                <div className="finding-meta">
                  <span>类型: <strong>{selectedFinding.vulnerability_type}</strong></span>
                  <span>CWE: <strong>{selectedFinding.cwe || "n/a"}</strong></span>
                  <span>置信度: <strong>{selectedFinding.confidence?.toFixed?.(2) || "n/a"}</strong></span>
                  <span>可达性: <strong>{selectedFinding.reachability || "unknown"}</strong></span>
                  <span>可利用性: <strong>{selectedFinding.exploitability || "unknown"}</strong></span>
                  <span>建议验证: <strong>{selectedFinding.should_verify ? "是" : "否"}</strong></span>
                  <span>函数: <strong>{selectedFinding.function_name || "unknown"}</strong></span>
                  <span>Source: <strong>{selectedFinding.source || "unknown"}</strong></span>
                  <span>Sink: <strong>{selectedFinding.sink || "unknown"}</strong></span>
                </div>
                <p>{selectedFinding.chinese_summary || selectedFinding.description}</p>
                <ChainGraphView graph={selectedFinding.chain_graph} />
                <h3>触发条件</h3>
                <ul>{(selectedFinding.trigger_conditions || []).map((item) => <li key={item}>{item}</li>)}</ul>
                <h3>静态证据</h3>
                <ul>{(selectedFinding.evidence || []).map((item) => <li key={item}>{item}</li>)}</ul>
                <h3>验证证据</h3>
                <VerificationEvidencePanel verification={selectedFinding.verification} />
                <TracePanel trace={selectedFinding.trace} />
                <h3>修复建议</h3>
                <p>{selectedFinding.recommendation || selectedFinding.verification_reason || "结合上下文补充输入验证、边界检查和回归测试。"}</p>
              </div>
            ) : <div className="empty">选择一个漏洞查看链路图和验证证据。</div>}
          </Panel>
        </section>

        <Panel title="报告" icon={<FileText size={18} />}>
          <ReportSummaryPanel task={task} findings={findings} report={report} />
        </Panel>
      </main>
    </div>
  );
}

function ToolStatusPanel({ tools }: { tools: ToolInfo[] }) {
  if (tools.length === 0) return <div className="empty">暂无工具状态。</div>;
  const groups = tools.reduce<Record<string, ToolInfo[]>>((acc, tool) => {
    const key = tool.capability || "other";
    acc[key] = acc[key] || [];
    acc[key].push(tool);
    return acc;
  }, {});
  const capabilities = Object.keys(groups).sort();
  return (
    <div className="tool-groups">
      {capabilities.map((capability) => {
        const items = groups[capability].sort((a, b) => Number(b.required) - Number(a.required) || a.name.localeCompare(b.name));
        const available = items.filter((item) => item.available).length;
        return (
          <div className="tool-group" key={capability}>
            <div className="group-head">
              <strong>{capability}</strong>
              <span>{available}/{items.length}</span>
            </div>
            <div className="tool-list">
              {items.map((tool) => (
                <div className={tool.available ? "tool-item ok" : "tool-item missing"} key={tool.name}>
                  <div className="tool-row">
                    <strong>{tool.name}</strong>
                    <span className={tool.required ? "required-chip" : "optional-chip"}>{tool.required ? "required" : "optional"}</span>
                  </div>
                  <small>{tool.available ? tool.version || "available" : tool.reason || "unavailable"}</small>
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function ProfileView({ profile }: { profile: ProjectProfile | null }) {
  if (!profile) return <div className="empty">画像将在 ReconAgent 完成后生成。</div>;
  const languages = Object.entries(profile.languages || {}).map(([name, count]) => `${name}:${count}`).join(", ") || "unknown";
  return (
    <div className="profile-box">
      <div className="profile-line"><span>类型</span><strong>{profile.project_type || "unknown"}</strong></div>
      <div className="profile-line"><span>语言</span><strong>{languages}</strong></div>
      <div className="profile-line"><span>框架</span><strong>{(profile.frameworks || []).join(", ") || "unknown"}</strong></div>
      <EntryList title="构建入口" entries={profile.build_entries || []} />
      <EntryList title="运行入口" entries={profile.runtime_entries || []} />
      <EntryList title="测试入口" entries={profile.test_entries || []} />
      <EntryList title="验证入口" entries={profile.verification_entries || []} />
      <TagList title="弱化验证" values={profile.weak_verification_strategies || []} />
      <TagList title="不可运行原因" values={profile.non_runnable_reasons || []} />
      <TagList title="攻击优先级" values={profile.attack_priorities || []} />
      <TagList title="验证提示" values={profile.verification_hints || []} />
      <RecommendedTools details={profile.recommended_tool_details || []} />
      <ObjectList title="依赖风险摘要" items={profile.dependency_findings_summary || []} />
    </div>
  );
}

function EntryList({ title, entries }: { title: string; entries: ProfileEntry[] }) {
  return (
    <div className="profile-section">
      <h3>{title}</h3>
      {entries.length === 0 && <small>none</small>}
      {entries.slice(0, 5).map((entry, index) => (
        <div className="profile-entry" key={`${title}-${entry.kind}-${entry.file}-${index}`}>
          <strong>{entry.kind}</strong>
          <span>{entry.file}</span>
          {entry.command && <code>{entry.command}</code>}
        </div>
      ))}
    </div>
  );
}

function TagList({ title, values }: { title: string; values: string[] }) {
  return (
    <div className="profile-section">
      <h3>{title}</h3>
      <div className="tag-row">{values.length ? values.map((value) => <span key={value}>{value}</span>) : <small>none</small>}</div>
    </div>
  );
}

function RecommendedTools({ details }: { details: Array<Record<string, unknown>> }) {
  if (!details.length) return null;
  return (
    <div className="profile-section">
      <h3>推荐工具</h3>
      {details.slice(0, 8).map((item, index) => (
        <div className="profile-entry" key={`recommended-tool-${String(item.name || index)}`}>
          <strong>{String(item.name || "unknown")}</strong>
          <span>{String(item.reason || item.capability || "n/a")}</span>
          <code>{String(item.intended_phase || "phase n/a")} · {String(item.available ?? "unknown")}</code>
        </div>
      ))}
    </div>
  );
}

function ObjectList({ title, items }: { title: string; items: Array<Record<string, unknown>> }) {
  if (!items.length) return null;
  return (
    <div className="profile-section">
      <h3>{title}</h3>
      {items.slice(0, 6).map((item, index) => (
        <div className="profile-entry" key={`${title}-${index}`}>
          <strong>{String(item.package || item.id || item.name || `item-${index + 1}`)}</strong>
          <span>{String(item.summary || item.reason || item.status || JSON.stringify(item))}</span>
        </div>
      ))}
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

function TracePanel({ trace }: { trace?: TraceInfo }) {
  if (!trace) return <div className="empty">暂无追踪链。</div>;
  return (
    <div className="evidence-panel">
      <h3>证据追踪</h3>
      <div className="trace-grid">
        <TraceCell label="Candidate" value={trace.candidate_id} />
        <TraceCell label="Slice" value={trace.slice_id} />
        <TraceCell label="Dangerous Function" value={trace.dangerous_function_id} />
        <TraceCell label="Tool Runs" value={(trace.tool_run_refs || []).join(", ") || "none"} />
      </div>
      <ArtifactLinks ids={trace.artifact_refs || []} artifacts={trace.artifacts || []} />
      {Boolean(trace.tool_runs?.length) && (
        <details className="json-details">
          <summary>工具运行详情</summary>
          <pre>{JSON.stringify(trace.tool_runs, null, 2)}</pre>
        </details>
      )}
    </div>
  );
}

function TraceCell({ label, value }: { label: string; value?: string }) {
  return (
    <div className="trace-cell">
      <span>{label}</span>
      <strong>{value || "n/a"}</strong>
    </div>
  );
}

function VerificationEvidencePanel({ verification }: { verification?: VerificationInfo | null }) {
  if (!verification) return <div className="empty">暂无验证证据。</div>;
  const artifactIds = [
    ...((verification.evidence_artifact_ids || []) as string[]),
    ...((verification.exploit_artifact_ids || []) as string[]),
  ];
  return (
    <div className="evidence-panel">
      <div className="verification-grid">
        <TraceCell label="状态" value={verification.status || "not_verified"} />
        <TraceCell label="运行类型" value={verification.runtime_type || "n/a"} />
        <TraceCell label="策略" value={verification.strategy || "n/a"} />
        <TraceCell label="模式" value={verification.verification_mode || "n/a"} />
      </div>
      <p>{verification.reproduction || verification.checker_summary || "暂无复现结论。"}</p>
      <TagList title="环境缺口" values={(verification.environment_gaps || []) as string[]} />
      <ArtifactLinks ids={artifactIds} artifacts={[]} />
      <ObjectBlock title="执行记录" value={verification.execution} />
      <ObjectBlock title="Checker 判定" value={verification.checker_details} />
      <ObjectBlock title="环境画像" value={verification.environment} />
      {Boolean(verification.evidence?.length) && (
        <>
          <h3>证据摘要</h3>
          <ul>{(verification.evidence || []).map((item) => <li key={item}>{item}</li>)}</ul>
        </>
      )}
    </div>
  );
}

function ArtifactLinks({ ids, artifacts }: { ids: string[]; artifacts: ArtifactInfo[] }) {
  const merged = new Map<string, ArtifactInfo>();
  ids.filter(Boolean).forEach((id) => merged.set(id, { id }));
  artifacts.filter((item) => item.id).forEach((item) => merged.set(item.id, item));
  const items = [...merged.values()];
  if (!items.length) return <div className="artifact-empty">暂无 artifact。</div>;
  return (
    <div className="artifact-list">
      {items.map((artifact) => (
        <a key={artifact.id} href={`${API}/api/artifacts/${artifact.id}`} target="_blank" rel="noreferrer">
          <Download size={13} />
          <span>{artifact.kind || "artifact"}</span>
          <strong>{artifact.id}</strong>
        </a>
      ))}
    </div>
  );
}

function ObjectBlock({ title, value }: { title: string; value?: Record<string, unknown> }) {
  if (!value || Object.keys(value).length === 0) return null;
  return (
    <details className="json-details">
      <summary>{title}</summary>
      <pre>{JSON.stringify(value, null, 2)}</pre>
    </details>
  );
}

function ReportSummaryPanel({ task, findings, report }: { task: Task | null; findings: Finding[]; report: string }) {
  const severityCounts = countBy(findings.map((finding) => finding.severity || "unknown"));
  const verificationCounts = countBy(findings.map((finding) => verificationStatus(finding)));
  return (
    <div className="report-panel">
      <div className="report-actions">
        <a className="download" href={task ? `${API}/api/tasks/${task.id}/report.md` : "#"} target="_blank" rel="noreferrer">
          <Download size={16} />Markdown
        </a>
        <a className="download" href={task ? `${API}/api/tasks/${task.id}/report.json` : "#"} target="_blank" rel="noreferrer">
          <Download size={16} />JSON
        </a>
      </div>
      <div className="report-summary">
        <SummaryCard label="漏洞数" value={String(findings.length)} />
        <SummaryCard label="严重性" value={formatCounts(severityCounts)} />
        <SummaryCard label="验证状态" value={formatCounts(verificationCounts)} />
      </div>
      <div className="finding-index">
        {findings.slice(0, 12).map((finding) => (
          <span key={finding.id}>{finding.severity} · {finding.title}</span>
        ))}
        {findings.length === 0 && <span>暂无 finding 索引。</span>}
      </div>
      <pre className="report">{report || "任务完成后显示报告。"}</pre>
    </div>
  );
}

function SummaryCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="summary-card">
      <span>{label}</span>
      <strong>{value || "none"}</strong>
    </div>
  );
}

function countBy(values: string[]) {
  return values.reduce<Record<string, number>>((acc, value) => {
    acc[value] = (acc[value] || 0) + 1;
    return acc;
  }, {});
}

function formatCounts(counts: Record<string, number>) {
  const text = Object.entries(counts).map(([key, value]) => `${key}:${value}`).join(", ");
  return text || "none";
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

