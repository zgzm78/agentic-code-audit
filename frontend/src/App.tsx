import { lazy, startTransition, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { AnimatePresence, motion } from "motion/react";
import { api, API_BASE, createAbortController } from "./api/client";
import type { EventItem, Finding, MiningDebug, ProjectProfile, Task, ToolInfo } from "./components/types";
import AppShell from "./features/shell/AppShell";

const Overview = lazy(() => import("./features/overview/Overview"));
const FindingsWorkspace = lazy(() => import("./features/findings/FindingsWorkspace"));
const LiveAudit = lazy(() => import("./features/live/LiveAudit"));
const ReportView = lazy(() => import("./features/report/ReportView"));

const TERMINAL = new Set(["completed", "failed", "cancelled"]);
const SSE_EVENTS = [
  "task_created", "task_started", "progress", "stage_start", "stage_done",
  "mining_step_start", "mining_step_done", "tool_start", "tool_end", "tool_output",
  "finding", "verification", "debug_report", "report", "error", "task_failed",
  "task_cancelled", "task_completed", "heartbeat",
];
const MINIMUM_ASSEMBLY_MS = 1350;

export type AuditData = {
  tasks: Task[]; task: Task | null; events: EventItem[]; findings: Finding[];
  tools: ToolInfo[]; profile: ProjectProfile | null; debug: MiningDebug | null;
  report: string; health: Record<string, unknown> | null; busy: boolean; notice: string;
};

export type AuditActions = {
  selectTask: (id: string) => Promise<void>; createTask: (payload: Record<string, unknown>) => Promise<void>;
  startTask: () => Promise<void>; stopTask: () => Promise<void>; deleteTask: (id: string) => Promise<void>;
  shutdownSystem: () => Promise<void>;
  loadFinding: (finding: Finding) => Promise<Finding>;
};

function wait(ms: number) {
  return new Promise<void>((resolve) => window.setTimeout(resolve, ms));
}

function mergeEvents(current: EventItem[], incoming: EventItem[]) {
  if (!incoming.length) return current;
  const bySequence = new Map<number, EventItem>();
  current.forEach((event) => bySequence.set(event.sequence, event));
  incoming.forEach((event) => bySequence.set(event.sequence, event));
  return [...bySequence.values()].sort((a, b) => a.sequence - b.sequence);
}

export default function App() {
  const [data, setData] = useState<AuditData>({
    tasks: [], task: null, events: [], findings: [], tools: [], profile: null,
    debug: null, report: "", health: null, busy: true, notice: "正在连接审计引擎",
  });
  const navigate = useNavigate();
  const location = useLocation();
  const selectedTaskRef = useRef<string>();
  const syncInFlightRef = useRef<string>();
  const syncTimerRef = useRef<number>();
  const reportLoadedRef = useRef(new Set<string>());
  const detailRefreshAtRef = useRef(new Map<string, number>());
  const terminalDetailsLoadedRef = useRef(new Set<string>());
  const selectAbortRef = useRef<AbortController>();

  const refreshTasks = useCallback(async () => {
    const tasks = await api.tasks();
    startTransition(() => setData((prev) => ({ ...prev, tasks })));
    return tasks;
  }, []);

  const selectTask = useCallback(async (id: string) => {
    selectAbortRef.current?.abort();
    const controller = createAbortController();
    selectAbortRef.current = controller;
    const { signal } = controller;
    const startedAt = performance.now();
    selectedTaskRef.current = id;
    setData((prev) => ({ ...prev, busy: true, notice: "正在组装调查证据" }));
    try {
      const [task, events, profile, debug, report] = await Promise.all([
        api.task(id, signal),
        api.events(id, 0, signal).catch(() => [] as any[]),
        api.profile(id, signal).catch(() => null),
        api.miningDebug(id, signal).catch(() => null),
        api.report(id, signal).catch(() => ""),
      ]);
      if (signal.aborted || selectedTaskRef.current !== id) return;
      const remaining = MINIMUM_ASSEMBLY_MS - (performance.now() - startedAt);
      if (remaining > 0) await wait(remaining);
      if (signal.aborted || selectedTaskRef.current !== id) return;
      if (report) reportLoadedRef.current.add(id);
      detailRefreshAtRef.current.set(id, performance.now());
      if (TERMINAL.has(task.status)) terminalDetailsLoadedRef.current.add(id);
      else terminalDetailsLoadedRef.current.delete(id);
      setData((prev) => ({
        ...prev,
        task,
        events: mergeEvents([], events),
        findings: task.findings ?? [],
        profile,
        debug,
        report,
        tasks: prev.tasks.map((item) => item.id === task.id ? { ...item, ...task } : item),
        busy: false,
        notice: "",
      }));
    } catch (error) {
      if (!signal.aborted && selectedTaskRef.current === id) {
        setData((prev) => ({ ...prev, busy: false, notice: (error as Error).message }));
      }
    }
  }, []);

  const afterRef = useRef(0);

  const refreshSelectedTask = useCallback(async (id: string) => {
    if (selectedTaskRef.current !== id || syncInFlightRef.current === id) return;
    syncInFlightRef.current = id;
    try {
      const now = performance.now();
      const shouldRefreshDetails = !terminalDetailsLoadedRef.current.has(id) && now - (detailRefreshAtRef.current.get(id) || 0) >= 4000;
      const detailsPromise = shouldRefreshDetails
        ? Promise.all([api.profile(id).catch(() => null), api.miningDebug(id).catch(() => null)])
        : Promise.resolve<[ProjectProfile | null | undefined, MiningDebug | null | undefined]>([undefined, undefined]);
      const after = afterRef.current;
      const [task, events, initialDetails] = await Promise.all([api.task(id), api.events(id, after).catch(() => []), detailsPromise]);
      let [profile, debug] = initialDetails;
      if (shouldRefreshDetails) detailRefreshAtRef.current.set(id, now);
      if (TERMINAL.has(task.status) && !terminalDetailsLoadedRef.current.has(id)) {
        if (!shouldRefreshDetails) {
          [profile, debug] = await Promise.all([api.profile(id).catch(() => null), api.miningDebug(id).catch(() => null)]);
          detailRefreshAtRef.current.set(id, performance.now());
        }
        terminalDetailsLoadedRef.current.add(id);
      }
      let report: string | undefined;
      if (task.status === "completed" && !reportLoadedRef.current.has(id)) {
        report = await api.report(id).catch(() => "");
        if (report) reportLoadedRef.current.add(id);
      }
      if (selectedTaskRef.current !== id) return;
      startTransition(() => setData((prev) => {
        const merged = mergeEvents(prev.events, events);
        afterRef.current = merged.reduce((max, e) => Math.max(max, e.sequence), 0);
        return {
          ...prev,
          task,
          events: merged,
          findings: task.findings ?? prev.findings,
          profile: profile === undefined ? prev.profile : profile,
          debug: debug === undefined ? prev.debug : debug,
          report: report === undefined ? prev.report : report,
          tasks: prev.tasks.map((item) => item.id === task.id ? { ...item, ...task } : item),
        };
      }));
    } finally {
      if (syncInFlightRef.current === id) syncInFlightRef.current = undefined;
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    const boot = async () => {
      const startedAt = performance.now();
      const [health, tools, tasks] = await Promise.all([
        api.health().catch(() => null), api.tools().catch(() => []), api.tasks().catch(() => []),
      ]);
      if (cancelled) return;
      setData((prev) => ({ ...prev, health, tools, tasks, notice: health ? "正在建立证据上下文" : "后端暂未连接" }));
      if (tasks.length) {
        await selectTask(tasks[0].id);
      } else {
        const remaining = MINIMUM_ASSEMBLY_MS - (performance.now() - startedAt);
        if (remaining > 0) await wait(remaining);
        if (!cancelled) setData((prev) => ({ ...prev, busy: false, notice: health ? "" : prev.notice }));
      }
    };
    void boot();
    return () => { cancelled = true; };
  }, [selectTask]);

  useEffect(() => {
    const refreshHealth = () => api.health().then((health) => setData((prev) => ({ ...prev, health }))).catch(() => undefined);
    window.addEventListener("llm-settings-updated", refreshHealth);
    return () => window.removeEventListener("llm-settings-updated", refreshHealth);
  }, []);

  useEffect(() => {
    const refreshAmbientState = async () => {
      if (document.hidden) return;
      const [tasks, tools] = await Promise.all([api.tasks().catch(() => null), api.tools().catch(() => null)]);
      startTransition(() => setData((prev) => ({ ...prev, tasks: tasks ?? prev.tasks, tools: tools ?? prev.tools })));
    };
    const interval = window.setInterval(refreshAmbientState, 15000);
    return () => window.clearInterval(interval);
  }, []);

  useEffect(() => {
    const id = data.task?.id;
    if (!id) return;
    const sync = () => { if (!document.hidden) void refreshSelectedTask(id); };
    const interval = window.setInterval(sync, data.task?.status === "running" ? 1200 : 12000);
    const onVisibility = () => { if (!document.hidden) sync(); };
    window.addEventListener("focus", sync);
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      window.clearInterval(interval);
      window.removeEventListener("focus", sync);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [data.task?.id, data.task?.status, refreshSelectedTask]);

  useEffect(() => {
    const id = data.task?.id;
    if (!id || data.task.status !== "running") return;
    const after = data.events.reduce((latest, event) => Math.max(latest, event.sequence), 0);
    const stream = new EventSource(`${API_BASE}/api/tasks/${id}/events?after=${after}`);
    const scheduleSnapshot = (delay = 120) => {
      if (syncTimerRef.current) window.clearTimeout(syncTimerRef.current);
      syncTimerRef.current = window.setTimeout(() => void refreshSelectedTask(id), delay);
    };
    const receive = (message: MessageEvent) => {
      try {
        const payload = JSON.parse(message.data) as Partial<EventItem> & { status?: string };
        if (payload.sequence && payload.event_type) {
          setData((prev) => ({ ...prev, events: mergeEvents(prev.events, [payload as EventItem]) }));
        }
        scheduleSnapshot();
        if ((payload.status && TERMINAL.has(payload.status)) || ["task_completed", "task_cancelled", "task_failed"].includes(payload.event_type || "")) {
          stream.close();
        }
      } catch {
        scheduleSnapshot(0);
      }
    };
    stream.onmessage = receive;
    stream.onerror = () => scheduleSnapshot(0);
    SSE_EVENTS.forEach((name) => stream.addEventListener(name, receive));
    return () => {
      stream.close();
      if (syncTimerRef.current) window.clearTimeout(syncTimerRef.current);
    };
  }, [data.task?.id, data.task?.status, refreshSelectedTask]);

  const actions: AuditActions = useMemo(() => ({
    selectTask,
    createTask: async (payload) => {
      setData((prev) => ({ ...prev, busy: true, notice: "正在创建审计任务" }));
      try {
        const created = await api.createTask(payload); await refreshTasks(); await selectTask(created.task_id); navigate("/overview");
      } catch (error) { setData((prev) => ({ ...prev, busy: false, notice: (error as Error).message })); }
    },
    startTask: async () => { if (data.task) { await api.startTask(data.task.id); await selectTask(data.task.id); } },
    stopTask: async () => { if (data.task) { await api.cancelTask(data.task.id); await selectTask(data.task.id); } },
    deleteTask: async (id) => {
      await api.deleteTask(id);
      reportLoadedRef.current.delete(id);
      detailRefreshAtRef.current.delete(id);
      terminalDetailsLoadedRef.current.delete(id);
      const tasks = await refreshTasks();
      if (data.task?.id === id) {
        if (tasks[0]) await selectTask(tasks[0].id);
        else {
          selectedTaskRef.current = undefined;
          setData((prev) => ({ ...prev, task: null, findings: [], events: [], report: "" }));
        }
      }
    },
    shutdownSystem: async () => { await api.shutdownSystem(); },
    loadFinding: async (finding) => data.task ? api.finding(data.task.id, finding.id) : finding,
  }), [data.task, navigate, refreshTasks, selectTask]);

  return (
    <AppShell data={data} actions={actions}>
      <AnimatePresence mode="wait">
        <motion.div key={location.pathname} className="route-stage" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -5 }} transition={{ duration: .2 }}>
          <Suspense fallback={<div className="route-loader">正在切换观察模式</div>}>
            <Routes>
              <Route path="/overview" element={<Overview data={data} />} />
              <Route path="/findings" element={<FindingsWorkspace data={data} actions={actions} />} />
              <Route path="/live" element={<LiveAudit data={data} />} />
              <Route path="/report" element={<ReportView data={data} />} />
              <Route path="*" element={<Navigate to="/overview" replace />} />
            </Routes>
          </Suspense>
        </motion.div>
      </AnimatePresence>
    </AppShell>
  );
}
