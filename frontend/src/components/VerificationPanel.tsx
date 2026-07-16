import { Download, FlaskConical, PlayCircle, ShieldCheck } from "lucide-react";
import type { ReactNode } from "react";
import { API_BASE } from "../api/client";
import type { ArtifactInfo, ValidationTag, VerificationInfo } from "./types";
import { validationTags } from "./verificationTags";

type Props = { verification?: VerificationInfo | null };

export default function VerificationPanel({ verification }: Props) {
  if (!verification) return <div className="empty-state">暂无验证证据。</div>;

  const artifactIds = [
    ...((verification.evidence_artifact_ids || []) as string[]),
    ...((verification.exploit_artifact_ids || []) as string[]),
    ...((verification.artifact_ids || []) as string[]),
  ];
  const staticStage = (verification.static_verification || {}) as Record<string, unknown>;
  const dynamicStage = (verification.dynamic_verification || {}) as Record<string, unknown>;
  const checkerStage = (verification.checker_verdict || verification.checker_details || {}) as Record<string, unknown>;
  const blockedReason = String(verification.blocked_reason || dynamicStage.blocked_reason || checkerStage.blocked_reason || "");
  const recipe = (verification.verification_recipe || dynamicStage.verification_recipe || verification.verification_plan || {}) as Record<string, unknown>;
  const fallbackAttempts = (verification.fallback_attempts || []) as Array<Record<string, unknown>>;

  return (
    <div>
      <TagRow tags={validationTags(verification)} />

      <div className="verification-grid">
        <VItem label="最终状态" value={String(verification.status || "not_verified")} />
        <VItem label="Runtime" value={String(verification.runtime_type || "n/a")} />
        <VItem label="策略" value={String(verification.strategy || "n/a")} />
        <VItem label="验证模式" value={String(verification.verification_mode || "n/a")} />
        <VItem label="Proof level" value={String(verification.proof_level || "none")} />
        <VItem label="阻塞原因" value={blockedReason || "none"} />
      </div>

      {(verification.reproduction || verification.checker_summary) && (
        <p className="verification-note">{verification.reproduction || verification.checker_summary}</p>
      )}

      <div className="verification-stage-grid">
        <StageCard
          title="静态验证"
          icon={<ShieldCheck size={16} />}
          status={String(staticStage.static_status || verification.analysis_verdict || "unknown")}
          rows={[
            ["可达性", staticStage.reachability || "unknown"],
            ["可动态验证", boolText(staticStage.dynamic_eligible)],
            ["原因", staticStage.reason || verification.rejection_reason || "n/a"],
          ]}
          details={staticStage}
        />
        <StageCard
          title="动态验证"
          icon={<PlayCircle size={16} />}
          status={String(dynamicStage.status || (verification.dynamic_attempted ? "attempted" : "not_attempted"))}
          rows={[
            ["Runtime type", dynamicStage.runtime_type || verification.runtime_type || "n/a"],
            ["Build strategy", dynamicStage.build_strategy || verification.strategy || "n/a"],
            ["Oracle", dynamicStage.oracle || verification.oracle || "n/a"],
            ["Blocked reason", dynamicStage.blocked_reason || "none"],
          ]}
          details={dynamicStage}
        />
        <StageCard
          title="Checker 判定"
          icon={<FlaskConical size={16} />}
          status={String(checkerStage.status || verification.checker_status || verification.status || "unknown")}
          rows={[
            ["Checker", checkerStage.checker || verification.checker_details?.checker || "n/a"],
            ["Exit code", verification.exit_code ?? verification.execution?.exit_code ?? "n/a"],
            ["摘要", checkerStage.summary || verification.checker_summary || "n/a"],
            ["Blocked reason", checkerStage.blocked_reason || "none"],
          ]}
          details={checkerStage}
        />
      </div>

      <RecipeSummary recipe={recipe} />
      <FallbackAttempts attempts={fallbackAttempts} />

      {(verification.environment_gaps || []).length > 0 && (
        <div className="finding-section">
          <h4>环境缺口</h4>
          <div className="profile-tags">
            {(verification.environment_gaps || []).map((g) => (
              <span key={String(g)} className="profile-tag">{String(g)}</span>
            ))}
          </div>
        </div>
      )}

      <ArtifactLinks ids={artifactIds} artifacts={(verification.artifact_records || []) as ArtifactInfo[]} />

      {(verification.evidence || []).length > 0 && (
        <div className="finding-section">
          <h4>证据摘要</h4>
          <ul>{(verification.evidence || []).map((e, i) => <li key={i}>{String(e)}</li>)}</ul>
        </div>
      )}

      <ObjectBlock title="Execution record" value={verification.execution} />
      <ObjectBlock title="Verification plan" value={verification.verification_plan} />
      <ObjectBlock title="Environment image" value={verification.environment} />
    </div>
  );
}

function TagRow({ tags }: { tags: ValidationTag[] }) {
  return (
    <div className="verification-tag-row">
      {tags.map((tag, index) => (
        <span key={`${tag.stage}-${tag.status}-${index}`} className={`badge ${stageBadgeClass(String(tag.status || ""))}`} title={tag.reason || tag.checker || ""}>
          {tag.label || tag.status || "unknown"}
        </span>
      ))}
    </div>
  );
}

function RecipeSummary({ recipe }: { recipe?: Record<string, unknown> }) {
  if (!recipe || Object.keys(recipe).length === 0) return null;
  return (
    <div className="finding-section verification-recipe">
      <h4>验证方案</h4>
      <div className="verification-grid">
        <VItem label="目标函数" value={String(recipe.target_function || "unknown")} />
        <VItem label="Source" value={String(recipe.source || "unknown")} />
        <VItem label="Sink" value={String(recipe.sink || "unknown")} />
        <VItem label="Preferred build" value={String(recipe.preferred_build || "n/a")} />
        <VItem label="Runtime entry" value={String(recipe.runtime_entry || "n/a")} />
        <VItem label="Expected signal" value={String(recipe.expected_signal || recipe.oracle || "n/a")} />
      </div>
      {recipe.fallback_harness && <p>{String(recipe.fallback_harness)}</p>}
      {recipe.micro_proof && <p>{String(recipe.micro_proof)}</p>}
    </div>
  );
}

function FallbackAttempts({ attempts }: { attempts: Array<Record<string, unknown>> }) {
  if (!attempts.length) return null;
  return (
    <div className="finding-section">
      <h4>局部验证尝试</h4>
      <div className="fallback-attempts">
        {attempts.map((attempt, index) => (
          <div className="fallback-attempt" key={index}>
            <strong>{String(attempt.kind || "attempt")} · {String(attempt.status || "unknown")}</strong>
            <span>Exit code: {String(attempt.exit_code ?? "n/a")}</span>
            <code>{Array.isArray(attempt.command) ? attempt.command.join(" ") : "n/a"}</code>
          </div>
        ))}
      </div>
    </div>
  );
}

function VItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="verification-item">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function StageCard({
  title,
  icon,
  status,
  rows,
  details,
}: {
  title: string;
  icon: ReactNode;
  status: string;
  rows: Array<[string, unknown]>;
  details?: Record<string, unknown>;
}) {
  return (
    <div className="verification-stage-card">
      <div className="verification-stage-title">
        {icon}
        <strong>{title}</strong>
        <span className={`badge ${stageBadgeClass(status)}`}>{status}</span>
      </div>
      <div className="verification-stage-rows">
        {rows.map(([label, value]) => (
          <div key={label} className="verification-stage-row">
            <span>{label}</span>
            <strong>{String(value ?? "n/a")}</strong>
          </div>
        ))}
      </div>
      <ObjectBlock title={`${title} details`} value={details} compact />
    </div>
  );
}

function stageBadgeClass(status: string): string {
  if (["verified", "exploitable", "plausible", "passed", "ready"].includes(status)) return "badge-verified";
  if (["harness_reproduced", "partial_dynamic_proof", "partially_verified", "planned", "attempted", "weak_static_proof", "weak"].includes(status)) return "badge-partial";
  if (["blocked", "not_attempted", "blocked_static"].includes(status)) return "badge-blocked";
  if (["false_positive", "likely_false_positive", "not_reproducible", "failed", "rejected"].includes(status)) return "badge-false";
  if (status === "static_only") return "badge-static";
  return "badge-unverified";
}

function ArtifactLinks({ ids, artifacts }: { ids: string[]; artifacts: ArtifactInfo[] }) {
  const merged = new Map<string, ArtifactInfo>();
  ids.filter(Boolean).forEach((id) => merged.set(id, { id }));
  artifacts.filter((a) => a.id).forEach((a) => merged.set(a.id, a));
  const items = [...merged.values()];
  if (!items.length) return null;
  return (
    <div className="finding-section">
      <h4>Artifacts</h4>
      <div className="artifact-list">
        {items.map((a) => (
          <a key={a.id} href={`${API_BASE}/api/artifacts/${a.id}`} target="_blank" rel="noreferrer" className="artifact-link">
            <Download size={13} />
            <span>{a.kind || "artifact"}</span>
            <strong>{a.id}</strong>
          </a>
        ))}
      </div>
    </div>
  );
}

function ObjectBlock({ title, value, compact = false }: { title: string; value?: Record<string, unknown>; compact?: boolean }) {
  if (!value || Object.keys(value).length === 0) return null;
  return (
    <details className={`json-toggle ${compact ? "json-toggle-compact" : ""}`}>
      <summary>{title}</summary>
      <pre>{JSON.stringify(value, null, 2)}</pre>
    </details>
  );
}

function boolText(value: unknown): string {
  if (value === true) return "是";
  if (value === false) return "否";
  return "unknown";
}
