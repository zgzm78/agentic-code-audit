import {
  Activity,
  Bug,
  Download,
  FileText,
  GitBranch,
  Play,
  Radio,
  Square,
  Terminal,
  Zap,
} from "lucide-react";
import { API_BASE } from "../api/client";
import type { Task, EventItem, Finding, ToolInfo, ProjectProfile, MiningDebug } from "./types";
import ProgressBar from "./ProgressBar";
import StatCard from "./StatCard";
import Panel from "./Panel";
import AgentArchitecture from "./AgentArchitecture";
import ToolPanel from "./ToolPanel";
import ProfilePanel from "./ProfilePanel";
import MiningDebugPanel from "./MiningDebugPanel";
import EventLog from "./EventLog";
import FindingList from "./FindingList";
import FindingDetail from "./FindingDetail";
import ReportPanel from "./ReportPanel";

type Props = {
  task: Task | null;
  events: EventItem[];
  findings: Finding[];
  selectedFinding: Finding | null;
  tools: ToolInfo[];
  profile: ProjectProfile | null;
  miningDebug: MiningDebug | null;
  report: string;
  health: Record<string, unknown> | null;
  liveHint: string;
  progressPercent: number;
  progressPhase: string;
  progressRunning: boolean;
  progressDone: boolean;
  progressFailed: boolean;
  onStartTask: () => void;
  onStopTask: () => void;
  onOpenFindingDetail: (f: Finding) => void;
};

export default function Workspace({
  task, events, findings, selectedFinding, tools, profile, miningDebug, report,
  health, liveHint, progressPercent, progressPhase,
  progressRunning, progressDone, progressFailed,
  onStartTask, onStopTask, onOpenFindingDetail,
}: Props) {
  const toolAvail = tools.filter((t) => t.available).length;

  return (
    <main className="workspace">
      <div className="topbar">
        <div className="topbar-title">
          <h1>源码安全审计台</h1>
          <p>{task?.target || "从历史任务中选择，或创建一个新的审计任务。"}</p>
        </div>
        <div className="topbar-actions">
          {task && task.status !== "running" && task.status !== "completed" && (
            <button className="btn btn-primary" onClick={onStartTask}>
              <Play size={15} /> 开始审计
            </button>
          )}
          {task?.status === "running" && (
            <button className="btn btn-danger" onClick={onStopTask}>
              <Square size={14} /> 停止
            </button>
          )}
          <a className="btn btn-ghost" href={task ? `${API_BASE}/api/tasks/${task.id}/report.md` : "#"} target="_blank" rel="noreferrer">
            <Download size={15} /> 报告
          </a>
          <a className="btn btn-ghost" href={task ? `${API_BASE}/api/tasks/${task.id}/report.json` : "#"} target="_blank" rel="noreferrer">
            <Download size={15} /> JSON
          </a>
        </div>
      </div>

      <ProgressBar
        percent={progressPercent}
        phase={progressPhase}
        hint={liveHint}
        isRunning={progressRunning}
        isDone={progressDone}
        isFailed={progressFailed}
      />

      <div className="stats-row">
        <StatCard label="任务状态" value={task?.status || "none"} icon={<Activity size={16} />} color="primary" />
        <StatCard label="当前阶段" value={progressPhase} icon={<Zap size={16} />} color="warning" />
        <StatCard label="模型" value={String(health?.model || "unknown")} icon={<Terminal size={16} />} />
        <StatCard label="漏洞数" value={String(findings.length)} icon={<Bug size={16} />} color={findings.length > 0 ? "danger" : "default"} />
        <StatCard label="事件数" value={String(events.length)} icon={<Radio size={16} />} />
        <StatCard label="LLM" value={health?.llm_configured ? "已配置" : "未配置"} icon={<ShieldCheck size={16} />} color={health?.llm_configured ? "success" : "danger"} />
        <StatCard label="可用工具" value={`${toolAvail}/${tools.length}`} icon={<Zap size={16} />} color={toolAvail > 5 ? "success" : "warning"} />
      </div>

      <div className="content-grid">
        <div>
          <Panel title="Agent 架构" icon={<GitBranch size={16} />}>
            <AgentArchitecture />
          </Panel>
          <div style={{ height: 16 }} />
          <Panel title="工具模块" icon={<Terminal size={16} />}>
            <ToolPanel tools={tools} />
          </Panel>
          <div style={{ height: 16 }} />
          <Panel title="项目画像" icon={<FileText size={16} />}>
            <ProfilePanel profile={profile} />
          </Panel>
          <div style={{ height: 16 }} />
          <Panel title="Mining Debug" icon={<Terminal size={16} />}>
            <MiningDebugPanel task={task} debug={miningDebug} />
          </Panel>
        </div>
        <div className="workspace-main-column">
          <Panel title="漏洞列表" icon={<Bug size={16} />}>
            <FindingList findings={findings} onSelect={onOpenFindingDetail} />
          </Panel>
          <div style={{ height: 16 }} />
          <Panel title="漏洞详情与触发链路" icon={<Activity size={16} />} bodyClassName="panel-body-tall">
            <FindingDetail finding={selectedFinding} />
          </Panel>
        </div>
      </div>

      <Panel title="实时事件流" icon={<Radio size={16} />}>
        <EventLog events={events} />
      </Panel>
      <div style={{ height: 20 }} />

      <Panel title="审计报告" icon={<FileText size={16} />}>
        <ReportPanel task={task} findings={findings} report={report} />
      </Panel>
    </main>
  );
}
