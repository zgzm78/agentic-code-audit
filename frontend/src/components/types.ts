export type Task = {
  id: string;
  target: string;
  status: string;
  mode?: string;
  enable_native_build?: boolean;
  budget?: Record<string, unknown>;
  budget_usage?: Record<string, unknown>;
  model: string;
  created_at: string;
  started_at?: string;
  finished_at?: string;
  markdown_report?: string;
  findings?: Finding[];
  error?: string;
  current_agent?: string;
  current_phase?: string;
  progress_done?: number;
  progress_total?: number;
};

export type EventItem = {
  sequence: number;
  agent: string;
  event_type: string;
  message: string;
  metadata: Record<string, unknown>;
  created_at: string;
};

export type Finding = {
  id: string;
  title: string;
  severity: string;
  vulnerability_type: string;
  risk_domain?: string;
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
  call_graph?: ChainGraph;
  call_paths?: string[][];
  entry_points?: string[];
  interprocedural_flow?: Record<string, unknown>;
  analysis_backends?: string[];
  evidence_graph?: Record<string, unknown>;
  evidence?: string[];
  trigger_conditions?: string[];
  verification?: VerificationInfo | null;
  trace?: TraceInfo;
  artifact_refs?: string[];
  tool_run_refs?: string[];
  verification_reason?: string;
  recommendation?: string;
};

export type VerificationInfo = {
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
  static_verification?: Record<string, unknown>;
  dynamic_verification?: Record<string, unknown>;
  checker_verdict?: Record<string, unknown>;
  dynamic_attempted?: boolean;
  blocked_reason?: string;
  verification_recipe?: Record<string, unknown>;
  proof_level?: string;
  validation_tags?: ValidationTag[];
  fallback_attempts?: Array<Record<string, unknown>>;
  artifact_ids?: string[];
  artifact_records?: ArtifactInfo[];
  generated_artifacts?: string[];
  local_fallback?: boolean;
  [key: string]: unknown;
};

export type ValidationTag = {
  stage?: string;
  status?: string;
  label?: string;
  reason?: string;
  checker?: string;
};

export type MiningDebug = {
  tool_anchor_count_by_tool?: Record<string, number>;
  anchor_count_by_risk_domain?: Record<string, number>;
  dangerous_function_count_by_kind?: Record<string, number>;
  slice_count_by_language?: Record<string, number>;
  candidate_validity_breakdown?: Record<string, number>;
  invalid_candidate_reasons?: Record<string, number>;
  candidate_source_distribution?: Record<string, number>;
  candidate_count_by_risk_domain?: Record<string, number>;
  aggregation_input_count?: number;
  aggregation_output_count?: number;
  investigation_candidates?: Array<Record<string, unknown>>;
  finding_count_by_type?: Record<string, number>;
  finding_count_by_risk_domain?: Record<string, number>;
  finding_severity_distribution?: Record<string, number>;
  verification_queue_count?: number;
  mining_director_strategy?: Record<string, unknown>;
  initial_strategy?: Record<string, unknown>;
  validated_strategy?: Record<string, unknown>;
  rejected_strategy_items?: Array<Record<string, unknown>>;
  strategy_effects?: Record<string, unknown>;
  exploration_log_summary?: Array<Record<string, unknown>>;
  feedback_used?: Array<Record<string, unknown>>;
  budget?: Record<string, unknown>;
  budget_usage?: Record<string, unknown>;
};

export type ArtifactInfo = {
  id: string;
  kind?: string;
  path?: string;
  sha256?: string;
  size_bytes?: number;
  metadata?: Record<string, unknown>;
};

export type TraceInfo = {
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

export type ToolInfo = {
  name: string;
  capability: string;
  available: boolean;
  required: boolean;
  version?: string;
  reason?: string;
  execution_location?: "backend" | "sandbox";
  container?: string;
  network_policy?: string;
};

export type ProfileEntry = {
  kind: string;
  file: string;
  command?: string;
  evidence?: string;
  confidence?: number;
};

export type ProjectProfile = {
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

export type ChainGraph = {
  nodes: Array<{ id: string; label: string; type: string; file_path?: string; line?: number; detail?: string }>;
  edges: Array<{ source: string; target: string; type: string; label?: string }>;
};
