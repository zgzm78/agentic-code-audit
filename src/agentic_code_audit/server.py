from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import replace
from dataclasses import asdict
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel

from .audit_budget import AuditMode
from .config import Settings, save_runtime_llm_settings
from .llm import DeepSeekClient
from .pipeline import AuditPipeline
from .store import AuditStore
from .tools.runner import ToolRunner


APP_ROOT = Path.cwd()
DATA_DIR = APP_ROOT / "data"
REPORTS_DIR = APP_ROOT / "reports"
STORE = AuditStore(DATA_DIR / "agentic-code-audit.sqlite3")


def _sync_imported_reports() -> None:
    STORE.sync_report_directories(REPORTS_DIR)


app = FastAPI(title="Agentic Code Audit API", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class TaskCreate(BaseModel):
    target: str
    mode: str = "standard"
    enable_native_build: bool = False
    runtime_url: str = ""


class LLMSettingsUpdate(BaseModel):
    provider: str = "openai-compatible"
    base_url: str
    model: str
    api_key: str = ""


class SystemShutdownRequest(BaseModel):
    confirmation: str


class TaskCancelled(Exception):
    pass


@app.get("/api/health")
def health() -> dict[str, Any]:
    settings = Settings.load(APP_ROOT)
    return {
        "status": "ok",
        "llm_configured": bool(settings.llm_api_key),
        "llm_provider": settings.llm_provider,
        "deepseek_configured": bool(settings.deepseek_api_key),
        "model": settings.llm_model,
        "native_build_policy": "task_controlled",
        "build_network_policy": "bridge" if settings.build_network_enabled else "none",
        "sandbox_container": settings.sandbox_container,
        "sandbox_image": settings.sandbox_image,
        "system_shutdown_available": _system_shutdown_enabled(),
        "db": str(STORE.db_path),
    }


def _system_shutdown_enabled() -> bool:
    return os.environ.get("AUDIT_ALLOW_SYSTEM_SHUTDOWN", "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def _docker_output(*arguments: str) -> str:
    result = subprocess.run(
        ["docker", *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=8,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Docker control command failed")
    return result.stdout.strip()


def _compose_shutdown_targets() -> list[tuple[str, str]]:
    container_id = Path("/etc/hostname").read_text(encoding="utf-8").strip()
    project = _docker_output(
        "inspect",
        "--format",
        '{{ index .Config.Labels "com.docker.compose.project" }}',
        container_id,
    )
    if not project:
        raise RuntimeError("Backend is not running in a Docker Compose project")
    output = _docker_output(
        "ps",
        "--filter",
        f"label=com.docker.compose.project={project}",
        "--format",
        '{{.ID}}|{{.Label "com.docker.compose.service"}}',
    )
    targets: list[tuple[str, str]] = []
    for line in output.splitlines():
        target_id, _, service = line.partition("|")
        if target_id and all(character in "0123456789abcdef" for character in target_id.lower()):
            targets.append((target_id, service or "service"))
    targets.sort(key=lambda item: (item[1] == "backend", item[1]))
    if not targets or not any(service == "backend" for _, service in targets):
        raise RuntimeError("Compose backend container could not be identified")
    return targets


def _launch_compose_shutdown(targets: list[tuple[str, str]], delay_seconds: float = 1.5) -> None:
    other_ids = [target_id for target_id, service in targets if service != "backend"]
    backend_ids = [target_id for target_id, service in targets if service == "backend"]
    helper = """
import json
import subprocess
import sys
import time

delay = float(sys.argv[1])
other_ids = json.loads(sys.argv[2])
backend_ids = json.loads(sys.argv[3])
time.sleep(delay)
if other_ids:
    subprocess.run(["docker", "stop", "-t", "5", *other_ids], check=False)
if backend_ids:
    subprocess.Popen(
        ["docker", "stop", "-t", "5", *backend_ids],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
"""
    subprocess.Popen(
        [sys.executable, "-c", helper, str(delay_seconds), json.dumps(other_ids), json.dumps(backend_ids)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
    )


def _cancel_running_tasks_for_shutdown() -> int:
    cancelled = 0
    for task in STORE.list_tasks():
        if task.get("status") != "running":
            continue
        task_id = str(task["id"])
        STORE.mark_cancelled(task_id)
        STORE.add_event(
            task_id,
            "System",
            "task_cancelled",
            "系统关机，审计任务已停止",
            phase="cancelled",
        )
        cancelled += 1
    return cancelled


@app.post("/api/system/shutdown", status_code=202)
def shutdown_system(payload: SystemShutdownRequest, background_tasks: BackgroundTasks) -> dict[str, Any]:
    if not _system_shutdown_enabled():
        raise HTTPException(status_code=403, detail="System shutdown is disabled for this deployment")
    if payload.confirmation != "SHUTDOWN":
        raise HTTPException(status_code=400, detail="Shutdown confirmation is invalid")
    try:
        targets = _compose_shutdown_targets()
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    cancelled = _cancel_running_tasks_for_shutdown()
    background_tasks.add_task(_launch_compose_shutdown, targets)
    return {
        "status": "shutting_down",
        "services": [service for _, service in targets],
        "running_tasks_cancelled": cancelled,
    }


def _public_llm_settings(settings: Settings) -> dict[str, Any]:
    key = settings.llm_api_key
    return {
        "provider": settings.llm_provider,
        "base_url": settings.llm_base_url,
        "model": settings.llm_model,
        "api_key_configured": bool(key),
        "api_key_hint": f"••••{key[-4:]}" if len(key) >= 4 else ("••••" if key else ""),
        "runtime_override": (DATA_DIR / "llm-settings.json").is_file(),
    }


def _settings_from_payload(payload: LLMSettingsUpdate) -> Settings:
    current = Settings.load(APP_ROOT)
    base_url = payload.base_url.strip().rstrip("/")
    if base_url.endswith("/chat/completions"):
        base_url = base_url[: -len("/chat/completions")]
    if not base_url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Base URL must start with http:// or https://")
    if not payload.model.strip():
        raise HTTPException(status_code=400, detail="Model is required")
    return replace(
        current,
        llm_provider=payload.provider.strip() or "openai-compatible",
        llm_api_key=payload.api_key.strip() or current.llm_api_key,
        llm_base_url=base_url,
        llm_model=payload.model.strip(),
    )


@app.get("/api/settings/llm")
def get_llm_settings() -> dict[str, Any]:
    return _public_llm_settings(Settings.load(APP_ROOT))


@app.put("/api/settings/llm")
def update_llm_settings(payload: LLMSettingsUpdate) -> dict[str, Any]:
    settings = _settings_from_payload(payload)
    save_runtime_llm_settings(
        APP_ROOT,
        {
            "LLM_PROVIDER": settings.llm_provider,
            "LLM_API_KEY": settings.llm_api_key,
            "LLM_BASE_URL": settings.llm_base_url,
            "LLM_MODEL": settings.llm_model,
        },
    )
    return _public_llm_settings(settings)


@app.post("/api/settings/llm/test")
def test_llm_settings(payload: LLMSettingsUpdate) -> dict[str, Any]:
    settings = _settings_from_payload(payload)
    started = time.perf_counter()
    response = DeepSeekClient(settings).chat(
        "You are a connection health check.",
        "Reply with OK only.",
        timeout=30,
    )
    elapsed_ms = round((time.perf_counter() - started) * 1000)
    return {
        "ok": response.ok,
        "latency_ms": elapsed_ms,
        "model": settings.llm_model,
        "message": response.content[:120] if response.ok else "",
        "error": response.error if not response.ok else "",
    }


@app.get("/api/tools")
def list_tools() -> list[dict[str, Any]]:
    settings = Settings.load(APP_ROOT)
    runner = ToolRunner(settings)
    return [asdict(item) for item in runner.list_tools()]


@app.post("/api/tasks")
def create_task(payload: TaskCreate) -> dict[str, Any]:
    settings = Settings.load(APP_ROOT)
    if not settings.llm_api_key:
        raise HTTPException(status_code=400, detail="LLM API key is required.")
    try:
        mode = AuditMode.normalize(payload.mode).value
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    task_id = STORE.create_task(
        payload.target,
        mode,
        settings.llm_model,
        payload.runtime_url,
        payload.enable_native_build,
        llm_provider=settings.llm_provider,
    )
    return {"task_id": task_id, "status": "queued"}


@app.post("/api/tasks/{task_id}/start")
def start_task(task_id: str, background_tasks: BackgroundTasks) -> dict[str, Any]:
    task = STORE.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="task not found")
    if task["status"] == "running":
        raise HTTPException(status_code=409, detail="task is already running")
    if task["status"] in {"completed", "failed", "cancelled"}:
        raise HTTPException(status_code=409, detail=f"{task['status']} task cannot be restarted")
    payload = {
        "target": task["target"],
        "mode": task["mode"],
        "runtime_url": task.get("runtime_url", ""),
        "enable_native_build": bool(task.get("enable_native_build", False)),
    }
    background_tasks.add_task(_run_task_threaded, task_id, payload)
    return {"task_id": task_id, "status": "starting"}


@app.post("/api/tasks/{task_id}/cancel")
def cancel_task(task_id: str) -> dict[str, Any]:
    task = STORE.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="task not found")
    if task["status"] in {"completed", "failed", "cancelled"}:
        return {"task_id": task_id, "status": task["status"]}
    STORE.mark_cancelled(task_id)
    STORE.add_event(task_id, "System", "task_cancelled", "用户已停止任务", phase="cancelled")
    return {"task_id": task_id, "status": "cancelled"}


@app.get("/api/tasks")
def list_tasks() -> list[dict[str, Any]]:
    _sync_imported_reports()
    return STORE.list_tasks()


@app.delete("/api/tasks/{task_id}")
def delete_task(task_id: str) -> dict[str, Any]:
    task = STORE.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="task not found")
    if task["status"] == "running":
        raise HTTPException(status_code=409, detail="running task must be cancelled before deletion")
    deleted = STORE.delete_task(task_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="task not found")
    return {"task_id": task_id, "deleted": True}


@app.get("/api/tasks/{task_id}")
def get_task(task_id: str) -> dict[str, Any]:
    _sync_imported_reports()
    task = STORE.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="task not found")
    task["findings"] = STORE.list_findings(task_id)
    return task


@app.get("/api/tasks/{task_id}/events")
async def stream_events(task_id: str, after: int = 0):
    _sync_imported_reports()
    if not STORE.get_task(task_id):
        raise HTTPException(status_code=404, detail="task not found")

    async def generator():
        cursor = after
        while True:
            events = STORE.get_events(task_id, cursor, 100)
            for event in events:
                cursor = max(cursor, int(event["sequence"]))
                yield f"event: {event['event_type']}\n"
                yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
            task = STORE.get_task(task_id)
            if task and task["status"] in {"completed", "failed", "cancelled"} and not events:
                yield "event: heartbeat\n"
                yield f"data: {json.dumps({'task_id': task_id, 'status': task['status']}, ensure_ascii=False)}\n\n"
                break
            await asyncio.sleep(1)

    return StreamingResponse(generator(), media_type="text/event-stream")


@app.get("/api/tasks/{task_id}/events/history")
def list_events(task_id: str, after: int = 0, limit: int = 500) -> list[dict[str, Any]]:
    _sync_imported_reports()
    if not STORE.get_task(task_id):
        raise HTTPException(status_code=404, detail="task not found")
    return STORE.get_events(task_id, after, limit)


@app.get("/api/tasks/{task_id}/findings")
def list_findings(task_id: str) -> list[dict[str, Any]]:
    _sync_imported_reports()
    return STORE.list_findings(task_id)


@app.get("/api/tasks/{task_id}/profile")
def get_profile(task_id: str) -> dict[str, Any]:
    _sync_imported_reports()
    if not STORE.get_task(task_id):
        raise HTTPException(status_code=404, detail="task not found")
    profile = STORE.get_project_profile(task_id)
    if not profile:
        raise HTTPException(status_code=404, detail="profile not found")
    return profile


@app.get("/api/tasks/{task_id}/findings/{finding_id}")
def get_finding(task_id: str, finding_id: str) -> dict[str, Any]:
    _sync_imported_reports()
    finding = STORE.get_finding(task_id, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="finding not found")
    return finding


@app.get("/api/tasks/{task_id}/report.md")
def get_report(task_id: str):
    _sync_imported_reports()
    task = STORE.get_task(task_id)
    if not task or not task.get("markdown_report"):
        raise HTTPException(status_code=404, detail="report not found")
    path = Path(task["markdown_report"])
    if not path.exists():
        raise HTTPException(status_code=404, detail="report file not found")
    return PlainTextResponse(path.read_text(encoding="utf-8"))


@app.get("/api/tasks/{task_id}/mining-debug.json")
def get_mining_debug(task_id: str):
    _sync_imported_reports()
    task = STORE.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="task not found")
    report_dir = task.get("report_dir") or ""
    debug_path = Path(report_dir) / "mining-debug.json" if report_dir else None
    if not debug_path or not debug_path.exists():
        raise HTTPException(status_code=404, detail="mining-debug.json not found")
    return FileResponse(debug_path, media_type="application/json", filename="mining-debug.json")


@app.get("/api/tasks/{task_id}/report.json")
def get_json_report(task_id: str):
    _sync_imported_reports()
    task = STORE.get_task(task_id)
    if not task or not task.get("json_report"):
        raise HTTPException(status_code=404, detail="report not found")
    path = Path(task["json_report"])
    if not path.exists():
        raise HTTPException(status_code=404, detail="report file not found")
    return FileResponse(path, media_type="application/json", filename="audit-report.json")


@app.get("/api/artifacts/{artifact_id}")
def get_artifact(artifact_id: str):
    artifact = STORE.get_artifact(artifact_id)
    if not artifact:
        raise HTTPException(status_code=404, detail="artifact not found")
    path = Path(artifact["path"])
    if not path.exists():
        raise HTTPException(status_code=404, detail="artifact file not found")
    return FileResponse(path)


def _run_task_threaded(task_id: str, payload: dict[str, Any]) -> None:
    thread = threading.Thread(target=_run_task, args=(task_id, payload), daemon=True)
    thread.start()


def _run_task(task_id: str, payload: dict[str, Any]) -> None:
    current = STORE.get_task(task_id)
    if current and current["status"] == "cancelled":
        return
    if not STORE.mark_running(task_id, "Orchestrator", "task_started"):
        return
    STORE.add_event(task_id, "Orchestrator", "task_started", "审计任务开始", payload, phase="task_started")
    try:
        settings = Settings.load(APP_ROOT)
        output_dir = REPORTS_DIR / task_id
        STORE.add_event(
            task_id,
            "InputAgent",
            "progress",
            "解析目标并准备工作区",
            {"progress_done": 0, "progress_total": 8},
            phase="resolve_target",
        )

        def event_sink(agent: str, event_type: str, message: str, metadata: dict[str, Any]) -> None:
            task = STORE.get_task(task_id)
            if task and task["status"] == "cancelled":
                raise TaskCancelled("任务已被用户停止")
            STORE.add_event(task_id, agent, event_type, message, metadata)

        pipeline = AuditPipeline(settings, event_sink=event_sink)
        artifacts = pipeline.run(
            payload["target"],
            output_dir,
            runtime_url=payload.get("runtime_url", ""),
            mode=payload.get("mode", "standard"),
            enable_native_build=bool(payload.get("enable_native_build", False)),
        )
        task = STORE.get_task(task_id)
        if task and task["status"] == "cancelled":
            return
        for finding in artifacts.report.findings:
            STORE.add_event(
                task_id,
                "VulnerabilityMiningAgent",
                "finding",
                finding.title,
                {
                    "id": finding.id,
                    "severity": finding.severity,
                    "type": finding.vulnerability_type,
                    "evidence_strength": finding.evidence_strength,
                    "should_verify": finding.should_verify,
                },
                phase="finding",
            )
        for verification in artifacts.report.verification_results:
            STORE.add_event(
                task_id,
                "VerificationAgent",
                "verification",
                f"{verification.finding_id}: {verification.status}",
                {"finding_id": verification.finding_id, "status": verification.status},
                phase="verification",
            )
        debug_data = artifacts.report.mining_debug
        STORE.add_event(
            task_id, "MiningDebug", "debug_report",
            f"mining-debug.json: {debug_data.get('candidate_validity_breakdown', {})}",
            debug_data,
            phase="debug",
        )

        STORE.save_report(task_id, artifacts.report, artifacts.json_path, artifacts.markdown_path)
        STORE.add_event(
            task_id,
            "ReportAgent",
            "report",
            "报告已生成",
            {"report": str(artifacts.markdown_path), "progress_done": 8, "progress_total": 8},
            phase="report",
        )
        STORE.mark_completed(task_id)
        STORE.add_event(task_id, "System", "task_completed", "审计任务完成", phase="completed")
    except TaskCancelled:
        STORE.mark_cancelled(task_id)
        STORE.add_event(task_id, "System", "task_cancelled", "用户已停止任务", phase="cancelled")
    except Exception as exc:  # noqa: BLE001
        STORE.mark_failed(task_id, str(exc))
        STORE.add_event(task_id, "System", "error", f"任务失败: {exc}", {"error": str(exc)}, phase="failed")

def _now() -> str:
    from .models import utc_now

    return utc_now()


def main() -> None:
    uvicorn.run("agentic_code_audit.server:app", host="0.0.0.0", port=8000, reload=False)


if __name__ == "__main__":
    main()
