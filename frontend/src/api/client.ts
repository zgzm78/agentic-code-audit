import type { MiningDebug, ProjectProfile, Task, ToolInfo } from "../components/types";

export const API_BASE = (import.meta as any).env?.VITE_API_BASE_URL || "";

export type LLMSettings = {
  provider: string;
  base_url: string;
  model: string;
  api_key?: string;
  api_key_configured?: boolean;
  api_key_hint?: string;
  runtime_override?: boolean;
};

export type LLMTestResult = {
  ok: boolean;
  latency_ms: number;
  model: string;
  message: string;
  error: string;
};

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, init);
  if (!response.ok) {
    const payload = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(String(payload.detail || response.statusText));
  }
  return response.json() as Promise<T>;
}

export function createAbortController() {
  return new AbortController();
}

function query(path: string, params: Record<string, string | number>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") search.set(key, String(value));
  }
  const qs = search.toString();
  return qs ? `${path}?${qs}` : path;
}

export const api = {
  health: (signal?: AbortSignal) => request<Record<string, unknown>>("/api/health", signal ? { signal } : undefined),
  tools: (signal?: AbortSignal) => request<ToolInfo[]>("/api/tools", signal ? { signal } : undefined),
  tasks: (signal?: AbortSignal) => request<Task[]>("/api/tasks", signal ? { signal } : undefined),
  task: (id: string, signal?: AbortSignal) => request<Task>(`/api/tasks/${id}`, signal ? { signal } : undefined),
  events: (id: string, after?: number, signal?: AbortSignal) =>
    request<any[]>(query(`/api/tasks/${id}/events/history`, { after: after ?? 0 }), signal ? { signal } : undefined),
  profile: (id: string, signal?: AbortSignal) => request<ProjectProfile>(`/api/tasks/${id}/profile`, signal ? { signal } : undefined),
  miningDebug: (id: string, signal?: AbortSignal) => request<MiningDebug>(`/api/tasks/${id}/mining-debug.json`, signal ? { signal } : undefined),
  finding: (taskId: string, findingId: string, signal?: AbortSignal) =>
    request<any>(`/api/tasks/${taskId}/findings/${findingId}`, signal ? { signal } : undefined),
  createTask: (payload: Record<string, unknown>) => request<{ task_id: string }>("/api/tasks", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
  }),
  startTask: (id: string, signal?: AbortSignal) => request(`/api/tasks/${id}/start`, {
    method: "POST", signal,
  }),
  cancelTask: (id: string, signal?: AbortSignal) => request(`/api/tasks/${id}/cancel`, {
    method: "POST", signal,
  }),
  deleteTask: (id: string) => request(`/api/tasks/${id}`, { method: "DELETE" }),
  report: async (id: string, signal?: AbortSignal) => {
    const response = await fetch(`${API_BASE}/api/tasks/${id}/report.md`, signal ? { signal } : undefined);
    return response.ok ? response.text() : "";
  },
  llmSettings: () => request<LLMSettings>("/api/settings/llm"),
  saveLLMSettings: (payload: LLMSettings) => request<LLMSettings>("/api/settings/llm", {
    method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
  }),
  testLLMSettings: (payload: LLMSettings) => request<LLMTestResult>("/api/settings/llm/test", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
  }),
  shutdownSystem: () => request<{ status: string; services: string[]; running_tasks_cancelled: number }>("/api/system/shutdown", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ confirmation: "SHUTDOWN" }),
  }),
};
