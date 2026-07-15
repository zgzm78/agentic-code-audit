import { lazy, Suspense, useState, type ReactNode } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { Activity, BarChart3, Bug, ChevronDown, FileText, History, Menu, Play, Plus, Power, Search, Settings, Shield, Square, Trash2, X } from "lucide-react";
import type { AuditActions, AuditData } from "../../App";
import LLMSettingsModal from "../settings/LLMSettingsModal";

const EvidenceSingularity = lazy(() => import("./EvidenceSingularity"));

const NAV = [
  { to: "/overview", label: "总览", icon: BarChart3 },
  { to: "/findings", label: "调查", icon: Bug },
  { to: "/live", label: "实时", icon: Activity },
  { to: "/report", label: "报告", icon: FileText },
];
export default function AppShell({ data, actions, children }: { data: AuditData; actions: AuditActions; children: ReactNode }) {
  const location = useLocation();
  const mode = location.pathname.split("/")[1] || "overview";
  const [drawer, setDrawer] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [navExpanded, setNavExpanded] = useState(true);
  const [shutdownOpen, setShutdownOpen] = useState(false);
  const [shutdownPhase, setShutdownPhase] = useState<"confirm" | "requesting" | "offline" | "error">("confirm");
  const [shutdownError, setShutdownError] = useState("");
  const shutdownAvailable = data.health?.system_shutdown_available === true;
  const openShutdown = () => {
    setShutdownPhase("confirm");
    setShutdownError("");
    setShutdownOpen(true);
  };
  const confirmShutdown = async () => {
    setShutdownPhase("requesting");
    setShutdownError("");
    try {
      await actions.shutdownSystem();
      setShutdownPhase("offline");
    } catch (error) {
      setShutdownError((error as Error).message);
      setShutdownPhase("error");
    }
  };
  return (
    <div className={`app-shell app-mode-${mode}`}>
      <Suspense fallback={null}><EvidenceSingularity status={data.task?.status} findings={data.findings.length} events={data.events.length} busy={data.busy} taskId={data.task?.id} currentAgent={data.task?.current_agent} /></Suspense>
      <div className="singularity-chrome" aria-hidden="true"><span>ACA // EVIDENCE SINGULARITY</span><b>FORENSIC LINK {data.health ? "STABLE" : "WAITING"}</b><i /><i /></div>
      <aside className={`mode-dock ${navExpanded ? "expanded" : "collapsed"}`} aria-label="观察模式">
        <button className="mode-dock-toggle" onClick={() => setNavExpanded((value) => !value)} aria-expanded={navExpanded} title={navExpanded ? "折叠观察模式" : "展开观察模式"}><Shield size={20} /></button>
        {navExpanded && <>
          <nav>{NAV.map((item) => <NavLink key={item.to} to={item.to} className={({ isActive }) => `mode-dock-link ${isActive ? "active" : ""}`}><item.icon size={17} /><span>{item.label}</span></NavLink>)}</nav>
          <div className="mode-dock-tools"><button onClick={() => setSettingsOpen(true)} title="LLM 配置" aria-label="LLM 配置"><Settings size={16} /></button><button onClick={() => setDrawer(true)} title="任务历史" aria-label="任务历史"><History size={16} /></button><button className="shutdown-trigger" onClick={openShutdown} disabled={!shutdownAvailable} title={shutdownAvailable ? "关闭审计系统" : "当前部署未启用系统关机"} aria-label="关闭审计系统"><Power size={16} /></button></div>
        </>}
      </aside>

      <div className="app-main">
        <header className="command-bar">
          <span className="command-coordinate">SYS.49 / NODE.08</span>
          <button className="mobile-menu" onClick={() => setDrawer(true)}><Menu size={19} /></button>
          <button className="mobile-settings" onClick={() => setSettingsOpen(true)} aria-label="LLM 配置"><Settings size={18} /></button>
          <button className="task-switcher" onClick={() => setDrawer(true)}>
            <span className={`status-orbit ${data.task?.status || "idle"}`} />
            <span><small>当前调查</small><strong>{shortTarget(data.task?.target) || "选择审计任务"}</strong></span>
            <ChevronDown size={16} />
          </button>
          <div className="command-search"><Search size={16} /><span>搜索漏洞、CWE 或文件</span><kbd>⌘ K</kbd></div>
          <button className="engine-state" onClick={() => setSettingsOpen(true)}><i className={data.health?.llm_configured ? "online" : ""} /><span>{data.health ? String(data.health.model || "LLM 未配置") : "离线模式"}</span></button>
          {data.task && data.task.status !== "running" && !["completed", "failed", "cancelled"].includes(data.task.status) && <button className="action-primary" onClick={actions.startTask}><Play size={15} />开始审计</button>}
          {data.task?.status === "running" && <button className="action-danger" onClick={actions.stopTask}><Square size={14} />停止</button>}
        </header>
        {data.notice && !data.busy && <div className="system-notice">{data.notice}</div>}
        {children}
      </div>

      {data.busy && <SingularityLoader message={data.notice} />}

      <div className={`drawer-scrim ${drawer ? "open" : ""}`} onClick={() => setDrawer(false)} />
      <aside className={`task-drawer ${drawer ? "open" : ""}`}>
        <div className="drawer-head"><div><small>WORKSPACE</small><h2>审计任务</h2></div><button onClick={() => setDrawer(false)}><X size={18} /></button></div>
        <button className="new-task-button" onClick={() => setCreateOpen((v) => !v)}><Plus size={17} />新建调查</button>
        {createOpen && <TaskForm onSubmit={async (payload) => { await actions.createTask(payload); setCreateOpen(false); setDrawer(false); }} />}
        <div className="drawer-label"><History size={13} />最近任务 <span>{data.tasks.length}</span></div>
        <div className="drawer-list">
          {data.tasks.map((task) => <div className={`drawer-task ${data.task?.id === task.id ? "active" : ""}`} key={task.id}>
            <button className="drawer-task-main" onClick={() => { actions.selectTask(task.id); setDrawer(false); }}>
              <span className={`task-status-line ${task.status}`} />
              <span><strong>{shortTarget(task.target)}</strong><small>{task.mode || "standard"} · {formatDate(task.created_at)}</small></span>
              <em>{task.status}</em>
            </button>
            {task.status !== "running" && <button className="task-delete" title="删除任务" onClick={() => confirm("确定删除该审计任务？") && actions.deleteTask(task.id)}><Trash2 size={14} /></button>}
          </div>)}
          {!data.tasks.length && <div className="drawer-empty">还没有审计记录</div>}
        </div>
      </aside>
      {settingsOpen && <LLMSettingsModal onClose={() => setSettingsOpen(false)} />}
      {shutdownOpen && <ShutdownDialog phase={shutdownPhase} running={data.task?.status === "running"} error={shutdownError} onClose={() => setShutdownOpen(false)} onConfirm={confirmShutdown} />}
    </div>
  );
}

function ShutdownDialog({ phase, running, error, onClose, onConfirm }: {
  phase: "confirm" | "requesting" | "offline" | "error";
  running: boolean;
  error: string;
  onClose: () => void;
  onConfirm: () => void;
}) {
  const locked = phase === "requesting" || phase === "offline";
  return <div className={`shutdown-backdrop phase-${phase}`} role="dialog" aria-modal="true" aria-labelledby="shutdown-title">
    <div className="shutdown-dialog">
      <div className="shutdown-core" aria-hidden="true"><i /><i /><b /></div>
      <div className="shutdown-copy">
        <small>SYSTEM DISCONNECT</small>
        <h2 id="shutdown-title">{phase === "offline" ? "审计系统已离线" : phase === "requesting" ? "正在断开系统链路" : "关闭整个审计系统"}</h2>
        {phase === "confirm" && <p>{running ? "当前审计仍在运行。继续后任务会被标记为已取消，然后关闭全部服务。" : "此操作会关闭当前项目的前端、后端与验证沙箱。"}</p>}
        {phase === "requesting" && <p>正在保存任务状态并依次停止容器，请保持当前页面打开。</p>}
        {phase === "offline" && <p>所有服务已收到关机指令。重新启动时请运行 <code>docker compose up -d</code>。</p>}
        {phase === "error" && <p className="shutdown-error">{error || "关机请求未能执行，请检查 Docker 服务状态。"}</p>}
      </div>
      <div className="shutdown-links" aria-label="关机范围">
        {[["01", "审计任务"], ["02", "验证沙箱"], ["03", "前端界面"], ["04", "后端引擎"]].map(([index, label]) => <div key={index}><span>{index}</span><strong>{label}</strong><i /></div>)}
      </div>
      {!locked && <div className="shutdown-actions">
        <button className="shutdown-cancel" onClick={onClose} autoFocus>取消</button>
        <button className="shutdown-confirm" onClick={onConfirm}><Power size={16} />确认关闭</button>
      </div>}
      {phase === "requesting" && <div className="shutdown-status"><span />正在发送最终断联信号</div>}
      {phase === "offline" && <div className="shutdown-status complete"><span />FORENSIC LINK OFFLINE</div>}
    </div>
  </div>;
}

function TaskForm({ onSubmit }: { onSubmit: (payload: Record<string, unknown>) => Promise<void> }) {
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState("standard");
  const [runtime, setRuntime] = useState("");
  const [native, setNative] = useState(false);
  return <form className="new-task-form" onSubmit={(e) => { e.preventDefault(); onSubmit({ target, mode, runtime_url: runtime, enable_native_build: native }); }}>
    <label>仓库地址<input value={target} onChange={(e) => setTarget(e.target.value)} required /></label>
    <div className="form-row"><label>审计模式<select value={mode} onChange={(e) => setMode(e.target.value)}><option value="quick">快速</option><option value="standard">标准</option><option value="deep">深度</option></select></label><label>Runtime URL<input value={runtime} onChange={(e) => setRuntime(e.target.value)} placeholder="可选" /></label></div>
    <label className="toggle-row"><input type="checkbox" checked={native} onChange={(e) => setNative(e.target.checked)} /><span>允许 C/C++ Native Build</span></label>
    <button type="submit" className="action-primary">创建任务</button>
  </form>;
}

function shortTarget(target?: string) { return target?.replace(/\.git$/, "").split("/").slice(-2).join("/") || ""; }
function formatDate(value: string) { return new Date(value).toLocaleDateString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }); }

function SingularityLoader({ message }: { message?: string }) {
  return <div className="singularity-loader" role="status" aria-live="polite">
    <div className="singularity-loader-copy"><small>EVIDENCE SINGULARITY</small><strong>正在组装证据晶体</strong><p>{message || "正在连接审计上下文"}</p></div>
  </div>;
}
