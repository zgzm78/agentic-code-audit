from __future__ import annotations

import asyncio
import json
import threading
from dataclasses import asdict
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel

from .config import Settings
from .pipeline import AuditPipeline
from .store import AuditStore
from .tools.runner import ToolRunner


APP_ROOT = Path.cwd()
DATA_DIR = APP_ROOT / "data"
REPORTS_DIR = APP_ROOT / "reports"
STORE = AuditStore(DATA_DIR / "agentic-code-audit.sqlite3")

app = FastAPI(title="Agentic Code Audit API", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class TaskCreate(BaseModel):
    target: str
    mode: str = "full"
    enable_native_build: bool = False
    runtime_url: str = ""


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
        "native_build_policy": "auto",
        "db": str(STORE.db_path),
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
    task_id = STORE.create_task(
        payload.target,
        payload.mode,
        settings.llm_model,
        payload.runtime_url,
        False,
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
    task = STORE.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="task not found")
    task["findings"] = STORE.list_findings(task_id)
    return task


@app.get("/api/tasks/{task_id}/events")
async def stream_events(task_id: str, after: int = 0):
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
    if not STORE.get_task(task_id):
        raise HTTPException(status_code=404, detail="task not found")
    return STORE.get_events(task_id, after, limit)


@app.get("/api/tasks/{task_id}/findings")
def list_findings(task_id: str) -> list[dict[str, Any]]:
    return STORE.list_findings(task_id)


@app.get("/api/tasks/{task_id}/profile")
def get_profile(task_id: str) -> dict[str, Any]:
    if not STORE.get_task(task_id):
        raise HTTPException(status_code=404, detail="task not found")
    profile = STORE.get_project_profile(task_id)
    if not profile:
        raise HTTPException(status_code=404, detail="profile not found")
    return profile


@app.get("/api/tasks/{task_id}/findings/{finding_id}")
def get_finding(task_id: str, finding_id: str) -> dict[str, Any]:
    finding = STORE.get_finding(task_id, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="finding not found")
    return finding


@app.get("/api/tasks/{task_id}/report.md")
def get_report(task_id: str):
    task = STORE.get_task(task_id)
    if not task or not task.get("markdown_report"):
        raise HTTPException(status_code=404, detail="report not found")
    path = Path(task["markdown_report"])
    if not path.exists():
        raise HTTPException(status_code=404, detail="report file not found")
    return PlainTextResponse(path.read_text(encoding="utf-8"))


@app.get("/api/tasks/{task_id}/report.json")
def get_json_report(task_id: str):
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
        artifacts = pipeline.run(payload["target"], output_dir, runtime_url=payload.get("runtime_url", ""))
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

