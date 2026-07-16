import { Download } from "lucide-react";
import { API_BASE } from "../api/client";
import type { Task, Finding } from "./types";
import { orderedRiskGroups, riskDomainOf } from "./riskDomain";

type Props = {
  task: Task | null;
  findings: Finding[];
  report: string;
};

function verifStatus(f: Finding): string {
  return String(f.verification?.status || "not_verified");
}

export default function ReportPanel({ task, findings, report }: Props) {
  const sevCounts = countBy(findings.map((f) => f.severity || "unknown"));
  const verifCounts = countBy(findings.map((f) => verifStatus(f)));
  const domainCounts = countBy(findings.map((f) => riskDomainOf(f)));
  const sourceFindings = findings.filter((f) => riskDomainOf(f) === "source_code");
  const staticOnly = findings.filter((f) => verifStatus(f) === "static_only").length;
  const dynamicAttempted = findings.filter((f) => Boolean(f.verification?.dynamic_attempted)).length;

  return (
    <div>
      <div className="report-actions">
        <a className="btn btn-ghost btn-sm" href={task ? `${API_BASE}/api/tasks/${task.id}/report.md` : "#"} target="_blank" rel="noreferrer">
          <Download size={14} /> Markdown
        </a>
        <a className="btn btn-ghost btn-sm" href={task ? `${API_BASE}/api/tasks/${task.id}/report.json` : "#"} target="_blank" rel="noreferrer">
          <Download size={14} /> JSON
        </a>
        <a className="btn btn-ghost btn-sm" href={task ? `${API_BASE}/api/tasks/${task.id}/mining-debug.json` : "#"} target="_blank" rel="noreferrer">
          <Download size={14} /> Mining Debug
        </a>
      </div>

      <div className="report-summary report-summary-wide">
        <ReportCard label="发现总数" value={findings.length} />
        <ReportCard label="源码漏洞" value={sourceFindings.length} />
        <ReportCard label="仅静态" value={staticOnly} />
        <ReportCard label="动态尝试" value={dynamicAttempted} />
        <ReportCard label="严重性" value={fmtCounts(sevCounts)} />
        <ReportCard label="验证状态" value={fmtCounts(verifCounts)} />
      </div>

      <div className="report-domain-grid">
        {orderedRiskGroups(findings).map((group) => (
          <div key={group.key} className="report-domain-card">
            <div>
              <strong>{group.label}</strong>
              <span>{group.description}</span>
            </div>
            <em>{domainCounts[group.key] || 0}</em>
          </div>
        ))}
        {!findings.length && <div className="report-domain-card"><strong>暂无分组</strong><span>运行审计后这里会显示结果。</span><em>0</em></div>}
      </div>

      <div className="finding-index">
        {sourceFindings.slice(0, 8).map((f) => (
          <span key={f.id} className="finding-index-chip">{f.severity} | {f.title}</span>
        ))}
        {!sourceFindings.length && <span className="finding-index-chip">暂无源码漏洞</span>}
      </div>

      <div className="report-body">{report || "任务完成后这里会显示 Markdown 报告。"}</div>
    </div>
  );
}

function ReportCard({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="report-card">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function countBy(values: string[]): Record<string, number> {
  return values.reduce<Record<string, number>>((acc, v) => { acc[v] = (acc[v] || 0) + 1; return acc; }, {});
}

function fmtCounts(c: Record<string, number>): string {
  return Object.entries(c).map(([k, v]) => `${k}:${v}`).join(", ") || "none";
}
