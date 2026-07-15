import React, { useState } from "react";
import { Boxes, History, ShieldAlert, Terminal, Trash2 } from "lucide-react";
import type { Task } from "./types";

type Props = {
  tasks: Task[];
  selectedTaskId: string | null;
  statusText: string;
  onCreateTask: (target: string, runtimeUrl: string, mode: string, enableNativeBuild: boolean) => void;
  onSelectTask: (taskId: string) => void;
  onDeleteTask: (taskId: string, status: string) => void;
};

function statusDot(status: string) {
  if (status === "completed") return "dot-completed";
  if (status === "running") return "dot-running";
  if (status === "failed" || status === "cancelled") return "dot-failed";
  return "dot-queued";
}

export default function Sidebar({ tasks, selectedTaskId, statusText, onCreateTask, onSelectTask, onDeleteTask }: Props) {
  const [target, setTarget] = useState("");
  const [runtimeUrl, setRuntimeUrl] = useState("");
  const [mode, setMode] = useState("standard");
  const [enableNativeBuild, setEnableNativeBuild] = useState(false);

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    onCreateTask(target, runtimeUrl, mode, enableNativeBuild);
  }

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <ShieldAlert size={26} />
        <div>
          <h2>Agentic Code Audit</h2>
          <span>AI 驱动 · 源码安全审计平台</span>
        </div>
      </div>

      <div className="sidebar-section">
        <div className="sidebar-section-title">
          <Terminal size={13} /> 新建任务
        </div>
        <form onSubmit={handleSubmit} className="task-form">
          <label>目标仓库 URL</label>
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="https://github.com/owner/repo.git"
            required
          />
          <label>Runtime URL（可选）</label>
          <input
            value={runtimeUrl}
            onChange={(e) => setRuntimeUrl(e.target.value)}
            placeholder="http://127.0.0.1:5000"
          />
          <label>运行模式</label>
          <select value={mode} onChange={(e) => setMode(e.target.value)}>
            <option value="quick">quick</option>
            <option value="standard">standard</option>
            <option value="deep">deep</option>
          </select>
          <label className="native-build-toggle">
            <input
              type="checkbox"
              checked={enableNativeBuild}
              onChange={(e) => setEnableNativeBuild(e.target.checked)}
            />
            <span>允许 C/C++ native build</span>
          </label>
          <button className="btn btn-primary" type="submit">
            <Boxes size={16} /> 创建任务
          </button>
          {statusText && <div className="status-text">{statusText}</div>}
        </form>
      </div>

      <div className="sidebar-section" style={{ flex: 1, display: "flex", flexDirection: "column", minHeight: 0 }}>
        <div className="sidebar-section-title">
          <History size={13} /> 历史任务
        </div>
        <div className="task-list">
          {tasks.length === 0 && (
            <div className="status-text" style={{ padding: "12px 0" }}>暂无历史任务</div>
          )}
          {tasks.map((item) => (
            <div key={item.id} className={`task-item${selectedTaskId === item.id ? " active" : ""}`}>
              <button className="task-item-main" onClick={() => onSelectTask(item.id)}>
                <span className="task-item-status">
                  <span className={`dot ${statusDot(item.status)}`} />
                  {item.status}
                </span>
                <span className="task-item-name">{item.target}</span>
                <span className="task-item-time">{new Date(item.created_at).toLocaleString()}</span>
              </button>
              <button
                className="task-item-delete"
                title="删除"
                aria-label="删除任务"
                onClick={() => onDeleteTask(item.id, item.status)}
                disabled={item.status === "running"}
              >
                <Trash2 size={13} />
              </button>
            </div>
          ))}
        </div>
      </div>
    </aside>
  );
}
