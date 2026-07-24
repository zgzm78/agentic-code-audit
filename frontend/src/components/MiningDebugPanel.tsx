import { Download } from "lucide-react";
import { API_BASE } from "../api/client";
import type { MiningDebug, Task } from "./types";

type Props = {
  task: Task | null;
  debug: MiningDebug | null;
};

export default function MiningDebugPanel({ task, debug }: Props) {
  if (!task) return <div className="empty-state">选择任务后可查看 Mining Debug 数据。</div>;
  if (!debug) {
    return (
      <div>
        <div className="debug-toolbar">
          <a className="btn btn-ghost btn-sm" href={`${API_BASE}/api/tasks/${task.id}/mining-debug.json`} target="_blank" rel="noreferrer">
            <Download size={14} /> mining-debug.json
          </a>
        </div>
        <div className="empty-state">Mining 阶段完成后会生成 debug 数据。</div>
      </div>
    );
  }

  const candidateValidity = debug.candidate_validity_breakdown || {};
  const aggregationInput = Number(debug.aggregation_input_count || 0);
  const aggregationOutput = Number(debug.aggregation_output_count || 0);
  const queueCount = Number(debug.verification_queue_count || 0);
  const investigationCandidates = debug.investigation_candidates || [];

  return (
    <div className="debug-panel">
      <div className="debug-toolbar">
        <a className="btn btn-ghost btn-sm" href={`${API_BASE}/api/tasks/${task.id}/mining-debug.json`} target="_blank" rel="noreferrer">
          <Download size={14} /> mining-debug.json
        </a>
      </div>

      <div className="debug-metric-grid">
        <Metric label="Anchors" value={sumRecord(debug.tool_anchor_count_by_tool)} />
        <Metric label="Slices" value={sumRecord(debug.slice_count_by_language)} />
        <Metric label="Candidates" value={Number(candidateValidity.total || 0)} />
        <Metric label="有效 / 无效" value={`${candidateValidity.valid || 0} / ${candidateValidity.invalid || 0}`} />
        <Metric label="待调查候选" value={investigationCandidates.length} />
        <Metric label="聚合输入 -> 输出" value={`${aggregationInput} -> ${aggregationOutput}`} />
        <Metric label="验证队列" value={queueCount} />
      </div>

      <div className="debug-grid">
        <CountBlock title="Anchors by tool" values={debug.tool_anchor_count_by_tool} />
        <CountBlock title="Anchors by domain" values={debug.anchor_count_by_risk_domain} />
        <CountBlock title="Candidates by domain" values={debug.candidate_count_by_risk_domain} />
        <CountBlock title="Findings by domain" values={debug.finding_count_by_risk_domain} />
        <CountBlock title="Findings by type" values={debug.finding_count_by_type} />
        <CountBlock title="无效 candidate 原因" values={debug.invalid_candidate_reasons} />
      </div>

      {investigationCandidates.length > 0 && (
        <section className="debug-candidate-block">
          <div>
            <h4>高价值待确认线索</h4>
            <p>这些候选缺少关键上下文或需要进一步验证，不会进入最终漏洞报告。</p>
          </div>
          <div className="debug-candidate-list">
            {investigationCandidates.slice(0, 20).map((candidate, index) => (
              <div className="debug-candidate-row" key={asText(candidate.id, String(index))}>
                <div>
                  <strong>{asText(candidate.title, asText(candidate.vulnerability_type, "candidate"))}</strong>
                  <span>
                    {asText(candidate.file_path, "")}:{asText(candidate.line_start, "-")} ·{" "}
                    {asText(candidate.function_name, "unknown")}
                  </span>
                </div>
                <small>Source: {asText(candidate.source, "unknown")}</small>
                <small>Sink: {asText(candidate.sink, "unknown")}</small>
                <em>{asText(candidate.triage_reason, asText(candidate.validity, "needs_context"))}</em>
              </div>
            ))}
          </div>
        </section>
      )}

      <ObjectDetails title="Budget" value={debug.budget} />
      <ObjectDetails title="Budget usage" value={debug.budget_usage} />
      <ObjectDetails title="Director strategy" value={debug.validated_strategy || debug.mining_director_strategy} />
      <ObjectDetails title="Strategy effects" value={debug.strategy_effects} />
      <ObjectDetails title="Exploration log summary" value={debug.exploration_log_summary} />
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="debug-metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function CountBlock({ title, values }: { title: string; values?: Record<string, number> }) {
  const entries = Object.entries(values || {}).filter(([, value]) => Number(value) > 0).slice(0, 8);
  return (
    <div className="debug-count-block">
      <h4>{title}</h4>
      {entries.length ? (
        <div className="debug-count-list">
          {entries.map(([key, value]) => (
            <div key={key} className="debug-count-row">
              <span>{key}</span>
              <strong>{value}</strong>
            </div>
          ))}
        </div>
      ) : (
        <p>none</p>
      )}
    </div>
  );
}

function ObjectDetails({ title, value }: { title: string; value?: unknown }) {
  if (!value || (typeof value === "object" && !Array.isArray(value) && Object.keys(value as Record<string, unknown>).length === 0)) {
    return null;
  }
  return (
    <details className="json-toggle">
      <summary>{title}</summary>
      <pre>{JSON.stringify(value, null, 2)}</pre>
    </details>
  );
}

function sumRecord(values?: Record<string, number>): number {
  return Object.values(values || {}).reduce((total, value) => total + Number(value || 0), 0);
}

function asText(value: unknown, fallback: string): string {
  if (value === null || value === undefined || value === "") return fallback;
  return String(value);
}
