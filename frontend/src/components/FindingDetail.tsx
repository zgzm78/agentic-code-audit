import type { Finding } from "./types";
import ChainGraphView from "./ChainGraph";
import VerificationPanel from "./VerificationPanel";
import { validationTags, verificationBadgeClass, verificationStatus } from "./verificationTags";

type Props = { finding: Finding | null };

export default function FindingDetail({ finding }: Props) {
  if (!finding) return <div className="empty-state">选择一个漏洞查看触发链路和验证证据。</div>;

  const vs = verificationStatus(finding);

  return (
    <div className="finding-detail">
      <h2>{finding.title}</h2>

      <div className="finding-detail-badges">
        <span className={`badge badge-sev-${finding.severity}`}>{finding.severity}</span>
        <span className={`badge ${verificationBadgeClass(vs)}`}>{vs}</span>
        <span className="badge badge-type">{finding.verification?.verification_mode || "not_verified"}</span>
        <span className="badge badge-type">{finding.evidence_strength || "weak"}</span>
        {validationTags(finding.verification).map((tag, index) => (
          <span key={`${tag.stage}-${index}`} className={`badge ${verificationBadgeClass(String(tag.status || ""))}`} title={tag.reason || tag.checker || ""}>
            {tag.label || tag.status}
          </span>
        ))}
      </div>

      <div className="finding-meta-grid">
        <MetaItem label="类型" value={finding.vulnerability_type} />
        <MetaItem label="风险域" value={finding.risk_domain || "unknown"} />
        <MetaItem label="CWE" value={finding.cwe || "n/a"} />
        <MetaItem label="置信度" value={finding.confidence?.toFixed?.(2) || "n/a"} />
        <MetaItem label="可达性" value={finding.reachability || "unknown"} />
        <MetaItem label="可利用性" value={finding.exploitability || "unknown"} />
        <MetaItem label="建议验证" value={finding.should_verify ? "是" : "否"} />
        <MetaItem label="阻塞原因" value={String(finding.verification?.blocked_reason || "none")} />
        <MetaItem label="函数" value={finding.function_name || "unknown"} />
        <MetaItem label="Source" value={finding.source || "unknown"} />
        <MetaItem label="Sink" value={finding.sink || "unknown"} />
      </div>

      <p className="finding-detail-desc">{finding.chinese_summary || finding.description}</p>

      <div className="finding-section chain-section">
        <h4>触发链路图</h4>
        <ChainGraphView graph={finding.chain_graph} />
      </div>

      {(finding.call_graph?.nodes?.length || 0) > 0 && (
        <div className="finding-section chain-section">
          <h4>函数调用连通图</h4>
          <ChainGraphView graph={finding.call_graph} />
        </div>
      )}

      {(finding.trigger_conditions || []).length > 0 && (
        <div className="finding-section">
          <h4>触发条件</h4>
          <ul>{(finding.trigger_conditions || []).map((c, i) => <li key={i}>{c}</li>)}</ul>
        </div>
      )}

      {(finding.evidence || []).length > 0 && (
        <div className="finding-section">
          <h4>静态证据</h4>
          <ul>{(finding.evidence || []).map((e, i) => <li key={i}>{e}</li>)}</ul>
        </div>
      )}

      <div className="finding-section verification-section">
        <h4>验证证据</h4>
        <VerificationPanel verification={finding.verification} />
      </div>

      <div className="finding-section">
        <h4>修复建议</h4>
        <p>{finding.recommendation || finding.verification_reason || "结合上下文补充输入校验、边界检查和回归测试。"}</p>
      </div>
    </div>
  );
}

function MetaItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="finding-meta-item">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
