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

export const api = {
  health: () => request<Record<string, unknown>>("/api/health"),
  tools: () => request<ToolInfo[]>("/api/tools"),
  tasks: () => request<Task[]>("/api/tasks"),
  task: (id: string) => request<Task>(`/api/tasks/${id}`),
  events: (id: string) => request<any[]>(`/api/tasks/${id}/events/history`),
  profile: (id: string) => request<ProjectProfile>(`/api/tasks/${id}/profile`),
  miningDebug: (id: string) => request<MiningDebug>(`/api/tasks/${id}/mining-debug.json`),
  finding: (taskId: string, findingId: string) => request<any>(`/api/tasks/${taskId}/findings/${findingId}`),
  createTask: (payload: Record<string, unknown>) => request<{ task_id: string }>("/api/tasks", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
  }),
  startTask: (id: string) => request(`/api/tasks/${id}/start`, { method: "POST" }),
  cancelTask: (id: string) => request(`/api/tasks/${id}/cancel`, { method: "POST" }),
  deleteTask: (id: string) => request(`/api/tasks/${id}`, { method: "DELETE" }),
  report: async (id: string) => {
    const response = await fetch(`${API_BASE}/api/tasks/${id}/report.md`);
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
