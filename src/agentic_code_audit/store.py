from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import threading
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .audit_budget import AuditBudget
from .models import ArtifactRecord, AuditReport, ProjectProfile, utc_now


TERMINAL_STATUSES = {"completed", "failed", "cancelled"}


class AuditStore:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.init()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def init(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                create table if not exists tasks (
                  id text primary key,
                  target text not null,
                  mode text not null,
                  model text not null,
                  status text not null,
                  runtime_url text default '',
                  enable_native_build integer default 0,
                  report_dir text default '',
                  json_report text default '',
                  markdown_report text default '',
                  error text default '',
                  created_at text not null,
                  started_at text,
                  finished_at text
                );
                create table if not exists agent_events (
                  id integer primary key autoincrement,
                  task_id text not null,
                  sequence integer not null,
                  agent text not null,
                  event_type text not null,
                  message text not null,
                  metadata text not null,
                  created_at text not null
                );
                create table if not exists tool_runs (task_id text, tool text, status text, data text);
                create table if not exists dangerous_functions (task_id text, item_id text, data text);
                create table if not exists program_slices (task_id text, item_id text, data text);
                create table if not exists candidates (task_id text, item_id text, data text);
                create table if not exists findings (task_id text, finding_id text, data text);
                create table if not exists verification_attempts (task_id text, finding_id text, data text);
                create table if not exists artifacts (
                  id text primary key,
                  task_id text not null,
                  kind text not null,
                  path text not null,
                  created_at text not null
                );
                create table if not exists project_profiles (
                  task_id text primary key,
                  data text not null,
                  created_at text not null
                );
                """
            )
            self._ensure_columns(
                conn,
                "tasks",
                {
                    "target_type": "text default 'unknown'",
                    "commit_hash": "text default ''",
                    "llm_provider": "text default 'deepseek'",
                    "llm_model": "text default ''",
                    "current_agent": "text default ''",
                    "current_phase": "text default ''",
                    "progress_done": "integer default 0",
                    "progress_total": "integer default 0",
                },
            )
            self._ensure_columns(conn, "agent_events", {"phase": "text default ''"})
            self._ensure_columns(
                conn,
                "tool_runs",
                {
                    "run_id": "text default ''",
                    "command": "text default '[]'",
                    "exit_code": "integer",
                    "duration_ms": "integer",
                    "stdout_artifact_id": "text default ''",
                    "stderr_artifact_id": "text default ''",
                    "parsed_artifact_id": "text default ''",
                    "summary": "text default ''",
                    "cache_key": "text default ''",
                    "cache_hit": "integer default 0",
                    "created_at": "text default ''",
                },
            )
            self._ensure_columns(
                conn,
                "verification_attempts",
                {
                    "strategy": "text default ''",
                    "plan": "text default '{}'",
                    "commands": "text default '[]'",
                    "scripts_artifact_ids": "text default '[]'",
                    "exit_code": "integer",
                    "stdout_artifact_id": "text default ''",
                    "stderr_artifact_id": "text default ''",
                    "generated_files": "text default '[]'",
                    "duration_ms": "integer",
                    "checker_verdict": "text default ''",
                    "checker_reason": "text default ''",
                    "environment": "text default '{}'",
                    "environment_gaps": "text default '[]'",
                    "execution": "text default '{}'",
                    "evidence_artifact_ids": "text default '[]'",
                    "exploit_artifact_ids": "text default '[]'",
                    "checker_details": "text default '{}'",
                    "local_fallback": "integer default 0",
                    "created_at": "text default ''",
                },
            )
            self._ensure_columns(
                conn,
                "artifacts",
                {
                    "sha256": "text default ''",
                    "size_bytes": "integer default 0",
                    "metadata": "text default '{}'",
                },
            )

    def create_task(
        self,
        target: str,
        mode: str,
        model: str,
        runtime_url: str,
        enable_native_build: bool,
        llm_provider: str = "deepseek",
        target_type: str | None = None,
    ) -> str:
        task_id = str(uuid.uuid4())
        target_type = target_type or self._infer_target_type(target)
        with self._lock, self.connect() as conn:
            conn.execute(
                """
                insert into tasks(
                  id,target,mode,model,status,runtime_url,enable_native_build,created_at,
                  target_type,llm_provider,llm_model,current_agent,current_phase,progress_done,progress_total
                )
                values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    task_id,
                    target,
                    mode,
                    model,
                    "queued",
                    runtime_url,
                    int(enable_native_build),
                    utc_now(),
                    target_type,
                    llm_provider,
                    model,
                    "System",
                    "queued",
                    0,
                    0,
                ),
            )
        self.add_event(task_id, "System", "task_created", f"任务已创建: {target}", {"target": target})
        return task_id

    def update_task(self, task_id: str, **fields: Any) -> None:
        if not fields:
            return
        with self._lock, self.connect() as conn:
            existing_columns = set(self._columns(conn, "tasks"))
            safe_fields = {key: value for key, value in fields.items() if key in existing_columns}
            if not safe_fields:
                return
            columns = ", ".join(f"{key}=?" for key in safe_fields)
            values = list(safe_fields.values()) + [task_id]
            conn.execute(f"update tasks set {columns} where id=?", values)

    def mark_running(self, task_id: str, agent: str = "Orchestrator", phase: str = "running") -> bool:
        task = self.get_task(task_id)
        if not task or task["status"] in TERMINAL_STATUSES:
            return False
        self.update_task(
            task_id,
            status="running",
            started_at=task.get("started_at") or utc_now(),
            current_agent=agent,
            current_phase=phase,
        )
        return True

    def mark_completed(self, task_id: str) -> None:
        self.update_task(
            task_id,
            status="completed",
            finished_at=utc_now(),
            current_agent="System",
            current_phase="completed",
            progress_done=1,
            progress_total=1,
        )

    def mark_failed(self, task_id: str, error: str) -> None:
        self.update_task(
            task_id,
            status="failed",
            error=error,
            finished_at=utc_now(),
            current_agent="System",
            current_phase="failed",
        )

    def mark_cancelled(self, task_id: str, error: str = "用户停止任务") -> None:
        self.update_task(
            task_id,
            status="cancelled",
            error=error,
            finished_at=utc_now(),
            current_agent="System",
            current_phase="cancelled",
        )

    def set_progress(
        self,
        task_id: str,
        agent: str,
        phase: str,
        progress_done: int | None = None,
        progress_total: int | None = None,
    ) -> None:
        fields: dict[str, Any] = {"current_agent": agent, "current_phase": phase}
        if progress_done is not None:
            fields["progress_done"] = progress_done
        if progress_total is not None:
            fields["progress_total"] = progress_total
        self.update_task(task_id, **fields)

    def add_event(
        self,
        task_id: str,
        agent: str,
        event_type: str,
        message: str,
        metadata: dict[str, Any] | None = None,
        phase: str = "",
    ) -> None:
        metadata = metadata or {}
        phase = phase or str(metadata.get("phase") or event_type)
        progress_done = self._int_or_none(metadata.get("progress_done"))
        progress_total = self._int_or_none(metadata.get("progress_total"))
        with self._lock, self.connect() as conn:
            row = conn.execute(
                "select coalesce(max(sequence),0)+1 as seq from agent_events where task_id=?",
                (task_id,),
            ).fetchone()
            sequence = int(row["seq"])
            conn.execute(
                """
                insert into agent_events(task_id,sequence,agent,event_type,message,metadata,created_at,phase)
                values(?,?,?,?,?,?,?,?)
                """,
                (
                    task_id,
                    sequence,
                    agent,
                    event_type,
                    message,
                    json.dumps(metadata, ensure_ascii=False),
                    utc_now(),
                    phase,
                ),
            )
            fields: dict[str, Any] = {"current_agent": agent, "current_phase": phase}
            if progress_done is not None:
                fields["progress_done"] = progress_done
            if progress_total is not None:
                fields["progress_total"] = progress_total
            columns = ", ".join(f"{key}=?" for key in fields)
            conn.execute(f"update tasks set {columns} where id=?", list(fields.values()) + [task_id])

    def get_task(self, task_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("select * from tasks where id=?", (task_id,)).fetchone()
        return self._normalize_task(dict(row)) if row else None

    def sync_report_directories(self, reports_dir: Path) -> int:
        if not reports_dir.exists() or not reports_dir.is_dir():
            return 0
        imported = 0
        with self.connect() as conn:
            existing_ids = {
                str(row["id"])
                for row in conn.execute("select id from tasks").fetchall()
            }
        for report_json in sorted(reports_dir.glob("*/audit-report.json")):
            task_id = report_json.parent.name
            if task_id in existing_ids:
                continue
            try:
                payload = json.loads(report_json.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if self.import_report_directory(task_id, report_json.parent, payload):
                existing_ids.add(task_id)
                imported += 1
        return imported

    def import_report_directory(self, task_id: str, report_dir: Path, payload: dict[str, Any]) -> bool:
        if not task_id or not payload:
            return False
        input_source = payload.get("input_source") if isinstance(payload.get("input_source"), dict) else {}
        target = str(input_source.get("original") or payload.get("target") or report_dir.name)
        mode = str(payload.get("mode") or "standard")
        llm_provider = str(payload.get("llm_provider") or "deepseek")
        llm_model = str(payload.get("llm_model") or payload.get("model") or "")
        created_at = str(payload.get("created_at") or utc_now())
        commit_hash = str(input_source.get("commit") or "")
        target_type = str(input_source.get("kind") or self._infer_target_type(target))
        json_path = report_dir / "audit-report.json"
        markdown_path = report_dir / "audit-report.md"
        with self._lock, self.connect() as conn:
            if conn.execute("select 1 from tasks where id=?", (task_id,)).fetchone():
                return False
            conn.execute(
                """
                insert into tasks(
                  id,target,mode,model,status,runtime_url,enable_native_build,report_dir,json_report,
                  markdown_report,error,created_at,started_at,finished_at,target_type,commit_hash,
                  llm_provider,llm_model,current_agent,current_phase,progress_done,progress_total
                )
                values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    task_id,
                    target,
                    mode,
                    llm_model,
                    "completed",
                    "",
                    0,
                    str(report_dir),
                    str(json_path),
                    str(markdown_path) if markdown_path.exists() else "",
                    "",
                    created_at,
                    created_at,
                    created_at,
                    target_type,
                    commit_hash,
                    llm_provider,
                    llm_model,
                    "System",
                    "imported",
                    1,
                    1,
                ),
            )
            self._import_report_payload(conn, task_id, payload, json_path, markdown_path)
        return True

    def list_tasks(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("select * from tasks order by created_at desc").fetchall()
        return [self._normalize_task(dict(row)) for row in rows]

    def delete_task(self, task_id: str, delete_files: bool = True) -> bool:
        with self._lock, self.connect() as conn:
            task = conn.execute("select * from tasks where id=?", (task_id,)).fetchone()
            if not task:
                return False
            artifact_rows = conn.execute("select path from artifacts where task_id=?", (task_id,)).fetchall()
            report_dir = str(task["report_dir"] or "")
            report_files = [str(task["json_report"] or ""), str(task["markdown_report"] or "")]
            conn.execute("delete from agent_events where task_id=?", (task_id,))
            conn.execute("delete from tool_runs where task_id=?", (task_id,))
            conn.execute("delete from dangerous_functions where task_id=?", (task_id,))
            conn.execute("delete from program_slices where task_id=?", (task_id,))
            conn.execute("delete from candidates where task_id=?", (task_id,))
            conn.execute("delete from findings where task_id=?", (task_id,))
            conn.execute("delete from verification_attempts where task_id=?", (task_id,))
            conn.execute("delete from artifacts where task_id=?", (task_id,))
            conn.execute("delete from project_profiles where task_id=?", (task_id,))
            conn.execute("delete from tasks where id=?", (task_id,))
        if delete_files:
            self._delete_task_files(report_dir, report_files, [str(row["path"] or "") for row in artifact_rows])
        return True

    def get_events(self, task_id: str, after: int = 0, limit: int = 500) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "select * from agent_events where task_id=? and sequence>? order by sequence asc limit ?",
                (task_id, after, limit),
            ).fetchall()
        output = []
        for row in rows:
            item = dict(row)
            item["metadata"] = json.loads(item.get("metadata") or "{}")
            item.setdefault("phase", item.get("event_type", ""))
            output.append(item)
        return output

    def save_report(self, task_id: str, report: AuditReport, json_path: Path, markdown_path: Path) -> None:
        with self._lock, self.connect() as conn:
            conn.execute("delete from tool_runs where task_id=?", (task_id,))
            conn.execute("delete from dangerous_functions where task_id=?", (task_id,))
            conn.execute("delete from program_slices where task_id=?", (task_id,))
            conn.execute("delete from candidates where task_id=?", (task_id,))
            conn.execute("delete from findings where task_id=?", (task_id,))
            conn.execute("delete from verification_attempts where task_id=?", (task_id,))
            conn.execute("delete from artifacts where task_id=?", (task_id,))
            conn.execute("delete from project_profiles where task_id=?", (task_id,))
            conn.execute(
                "insert into project_profiles(task_id,data,created_at) values(?,?,?)",
                (task_id, self._json(asdict(report.profile)), utc_now()),
            )
            for item in report.tool_results:
                self._register_artifact_records(conn, task_id, item.artifact_records)
                conn.execute(
                    """
                    insert into tool_runs(
                      task_id,run_id,tool,status,data,command,exit_code,duration_ms,stdout_artifact_id,
                      stderr_artifact_id,parsed_artifact_id,summary,cache_key,cache_hit,created_at
                    )
                    values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        task_id,
                        item.run_id,
                        item.tool,
                        item.status,
                        self._json(asdict(item)),
                        self._json(item.command),
                        item.exit_code,
                        item.duration_ms,
                        item.stdout_artifact_id,
                        item.stderr_artifact_id,
                        item.parsed_artifact_id,
                        item.summary,
                        item.cache_key,
                        int(item.cache_hit),
                        item.finished_at or utc_now(),
                    ),
                )
            for item in report.dangerous_functions:
                conn.execute(
                    "insert into dangerous_functions(task_id,item_id,data) values(?,?,?)",
                    (task_id, item.id, self._json(asdict(item))),
                )
            for item in report.program_slices:
                conn.execute(
                    "insert into program_slices(task_id,item_id,data) values(?,?,?)",
                    (task_id, item.id, self._json(asdict(item))),
                )
            for item in report.candidates:
                conn.execute(
                    "insert into candidates(task_id,item_id,data) values(?,?,?)",
                    (task_id, item.id, self._json(asdict(item))),
                )
            for item in report.findings:
                conn.execute(
                    "insert into findings(task_id,finding_id,data) values(?,?,?)",
                    (task_id, item.id, self._json(asdict(item))),
                )
            for item in report.verification_results:
                self._register_artifact_records(conn, task_id, item.artifact_records)
                conn.execute(
                    """
                    insert into verification_attempts(
                      task_id,finding_id,data,strategy,plan,commands,scripts_artifact_ids,exit_code,
                      stdout_artifact_id,stderr_artifact_id,generated_files,duration_ms,
                      checker_verdict,checker_reason,environment,environment_gaps,execution,
                      evidence_artifact_ids,exploit_artifact_ids,checker_details,local_fallback,created_at
                    )
                    values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        task_id,
                        item.finding_id,
                        self._json(asdict(item)),
                        item.strategy or item.verification_mode or item.method,
                        self._json(item.verification_plan),
                        self._json([item.target_command, item.sandbox_command]),
                        self._json(item.artifact_ids),
                        item.exit_code,
                        "",
                        "",
                        self._json(item.generated_artifacts),
                        None,
                        item.checker_status or item.status,
                        item.checker_summary,
                        self._json(item.environment),
                        self._json(item.environment_gaps),
                        self._json(item.execution),
                        self._json(item.evidence_artifact_ids),
                        self._json(item.exploit_artifact_ids),
                        self._json(item.checker_details),
                        int(item.local_fallback),
                        utc_now(),
                    ),
                )
            for kind, path in {"json_report": json_path, "markdown_report": markdown_path}.items():
                self._insert_artifact(conn, task_id, kind, path)
            conn.execute(
                """
                update tasks
                set json_report=?, markdown_report=?, report_dir=?, target_type=?, commit_hash=?,
                    llm_provider=?, llm_model=?, model=?
                where id=?
                """,
                (
                    str(json_path),
                    str(markdown_path),
                    str(json_path.parent),
                    report.input_source.kind,
                    report.input_source.commit,
                    report.llm_provider,
                    report.llm_model,
                    report.llm_model,
                    task_id,
                ),
            )

    def _import_report_payload(
        self,
        conn: sqlite3.Connection,
        task_id: str,
        payload: dict[str, Any],
        json_path: Path,
        markdown_path: Path,
    ) -> None:
        for table in (
            "tool_runs",
            "dangerous_functions",
            "program_slices",
            "candidates",
            "findings",
            "verification_attempts",
            "artifacts",
            "project_profiles",
            "agent_events",
        ):
            conn.execute(f"delete from {table} where task_id=?", (task_id,))

        profile = payload.get("profile") if isinstance(payload.get("profile"), dict) else {}
        conn.execute(
            "insert into project_profiles(task_id,data,created_at) values(?,?,?)",
            (task_id, self._json(profile), utc_now()),
        )

        for index, item in enumerate(payload.get("tool_results") or []):
            if not isinstance(item, dict):
                continue
            run_id = str(item.get("run_id") or item.get("id") or f"imported-tool-{index}")
            self._register_imported_artifacts(conn, task_id, item.get("artifact_records") or [])
            conn.execute(
                """
                insert into tool_runs(
                  task_id,run_id,tool,status,data,command,exit_code,duration_ms,stdout_artifact_id,
                  stderr_artifact_id,parsed_artifact_id,summary,cache_key,cache_hit,created_at
                )
                values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    task_id,
                    run_id,
                    str(item.get("tool") or "imported"),
                    str(item.get("status") or ""),
                    self._json(item),
                    self._json(item.get("command") or []),
                    item.get("exit_code"),
                    item.get("duration_ms"),
                    str(item.get("stdout_artifact_id") or ""),
                    str(item.get("stderr_artifact_id") or ""),
                    str(item.get("parsed_artifact_id") or ""),
                    str(item.get("summary") or ""),
                    str(item.get("cache_key") or ""),
                    int(bool(item.get("cache_hit"))),
                    str(item.get("finished_at") or item.get("created_at") or utc_now()),
                ),
            )

        for index, item in enumerate(payload.get("dangerous_functions") or []):
            self._insert_imported_item(conn, "dangerous_functions", "item_id", task_id, item, index, "danger")
        for index, item in enumerate(payload.get("program_slices") or []):
            self._insert_imported_item(conn, "program_slices", "item_id", task_id, item, index, "slice")
        for index, item in enumerate(payload.get("candidates") or []):
            self._insert_imported_item(conn, "candidates", "item_id", task_id, item, index, "candidate")

        for index, item in enumerate(payload.get("findings") or []):
            if not isinstance(item, dict):
                continue
            item_id = str(item.get("id") or f"imported-finding-{index}")
            conn.execute(
                "insert into findings(task_id,finding_id,data) values(?,?,?)",
                (task_id, item_id, self._json(item)),
            )

        for index, item in enumerate(payload.get("verification_results") or []):
            if not isinstance(item, dict):
                continue
            finding_id = str(item.get("finding_id") or item.get("id") or f"imported-verification-{index}")
            self._register_imported_artifacts(conn, task_id, item.get("artifact_records") or [])
            conn.execute(
                """
                insert into verification_attempts(
                  task_id,finding_id,data,strategy,plan,commands,scripts_artifact_ids,exit_code,
                  stdout_artifact_id,stderr_artifact_id,generated_files,duration_ms,
                  checker_verdict,checker_reason,environment,environment_gaps,execution,
                  evidence_artifact_ids,exploit_artifact_ids,checker_details,local_fallback,created_at
                )
                values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    task_id,
                    finding_id,
                    self._json(item),
                    str(item.get("strategy") or item.get("verification_mode") or item.get("method") or ""),
                    self._json(item.get("verification_plan") or item.get("verification_recipe") or {}),
                    self._json([item.get("target_command") or [], item.get("sandbox_command") or []]),
                    self._json(item.get("artifact_ids") or []),
                    item.get("exit_code"),
                    str(item.get("stdout_artifact_id") or ""),
                    str(item.get("stderr_artifact_id") or ""),
                    self._json(item.get("generated_artifacts") or []),
                    item.get("duration_ms"),
                    str(item.get("checker_status") or item.get("status") or ""),
                    str(item.get("checker_summary") or item.get("rejection_reason") or ""),
                    self._json(item.get("environment") or {}),
                    self._json(item.get("environment_gaps") or []),
                    self._json(item.get("execution") or {}),
                    self._json(item.get("evidence_artifact_ids") or []),
                    self._json(item.get("exploit_artifact_ids") or []),
                    self._json(item.get("checker_details") or {}),
                    int(bool(item.get("local_fallback"))),
                    utc_now(),
                ),
            )

        self._insert_artifact(conn, task_id, "json_report", json_path)
        if markdown_path.exists():
            self._insert_artifact(conn, task_id, "markdown_report", markdown_path)

        events = payload.get("agent_events") or []
        if events:
            for index, item in enumerate(events, start=1):
                if not isinstance(item, dict):
                    continue
                conn.execute(
                    """
                    insert into agent_events(task_id,sequence,agent,event_type,message,metadata,created_at,phase)
                    values(?,?,?,?,?,?,?,?)
                    """,
                    (
                        task_id,
                        index,
                        str(item.get("agent") or "System"),
                        str(item.get("action") or item.get("event_type") or "imported_event"),
                        str(item.get("detail") or item.get("message") or "导入历史事件"),
                        self._json(item.get("metadata") or {}),
                        str(item.get("started_at") or item.get("created_at") or utc_now()),
                        str(item.get("phase") or item.get("status") or "imported"),
                    ),
                )
        else:
            conn.execute(
                """
                insert into agent_events(task_id,sequence,agent,event_type,message,metadata,created_at,phase)
                values(?,?,?,?,?,?,?,?)
                """,
                (
                    task_id,
                    1,
                    "System",
                    "report_imported",
                    "从 reports 目录导入历史报告",
                    self._json({"json_report": str(json_path)}),
                    utc_now(),
                    "imported",
                ),
            )

    def list_findings(self, task_id: str) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("select finding_id,data from findings where task_id=?", (task_id,)).fetchall()
            verification_rows = conn.execute(
                "select finding_id,data from verification_attempts where task_id=?",
                (task_id,),
            ).fetchall()
        verifications = {row["finding_id"]: json.loads(row["data"]) for row in verification_rows}
        output = []
        for row in rows:
            finding = json.loads(row["data"])
            verification = verifications.get(row["finding_id"])
            finding["verification"] = verification
            if verification and not finding.get("verification_status"):
                finding["verification_status"] = verification.get("status", "not_verified")
            finding["trace"] = self._trace_summary(finding)
            output.append(finding)
        return output

    def get_finding(self, task_id: str, finding_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            finding = conn.execute(
                "select data from findings where task_id=? and finding_id=?",
                (task_id, finding_id),
            ).fetchone()
            verification = conn.execute(
                "select data from verification_attempts where task_id=? and finding_id=?",
                (task_id, finding_id),
            ).fetchone()
        if not finding:
            return None
        data = json.loads(finding["data"])
        data["verification"] = json.loads(verification["data"]) if verification else None
        data["trace"] = self._build_trace(task_id, data, include_objects=True)
        return data

    def get_artifact(self, artifact_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("select * from artifacts where id=?", (artifact_id,)).fetchone()
        if not row:
            return None
        item = dict(row)
        item["metadata"] = json.loads(item.get("metadata") or "{}")
        return item

    def save_project_profile(self, task_id: str, profile: ProjectProfile) -> None:
        with self._lock, self.connect() as conn:
            conn.execute(
                """
                insert into project_profiles(task_id,data,created_at)
                values(?,?,?)
                on conflict(task_id) do update set data=excluded.data, created_at=excluded.created_at
                """,
                (task_id, self._json(asdict(profile)), utc_now()),
            )

    def get_project_profile(self, task_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("select data from project_profiles where task_id=?", (task_id,)).fetchone()
        return json.loads(row["data"]) if row else None

    def _ensure_columns(self, conn: sqlite3.Connection, table: str, columns: dict[str, str]) -> None:
        existing = set(self._columns(conn, table))
        for name, definition in columns.items():
            if name not in existing:
                conn.execute(f"alter table {table} add column {name} {definition}")

    def _columns(self, conn: sqlite3.Connection, table: str) -> list[str]:
        return [row["name"] for row in conn.execute(f"pragma table_info({table})").fetchall()]

    def _insert_artifact(self, conn: sqlite3.Connection, task_id: str, kind: str, path: Path) -> str:
        artifact_id = str(uuid.uuid4())
        return self._insert_artifact_with_id(conn, task_id, artifact_id, kind, path)

    def _insert_artifact_with_id(
        self,
        conn: sqlite3.Connection,
        task_id: str,
        artifact_id: str,
        kind: str,
        path: Path,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        sha256, size_bytes = self._file_metadata(path)
        conn.execute(
            """
            insert or replace into artifacts(id,task_id,kind,path,created_at,sha256,size_bytes,metadata)
            values(?,?,?,?,?,?,?,?)
            """,
            (
                artifact_id,
                task_id,
                kind,
                str(path),
                utc_now(),
                sha256,
                size_bytes,
                self._json(metadata or {"name": path.name}),
            ),
        )
        return artifact_id

    def _register_artifact_records(
        self,
        conn: sqlite3.Connection,
        task_id: str,
        records: list[ArtifactRecord],
    ) -> None:
        for record in records:
            if not record.id or not record.path:
                continue
            self._insert_artifact_with_id(
                conn,
                task_id,
                record.id,
                record.kind,
                Path(record.path),
                metadata=record.metadata,
            )

    def _register_imported_artifacts(
        self,
        conn: sqlite3.Connection,
        task_id: str,
        records: list[dict[str, Any]],
    ) -> None:
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                continue
            raw_path = str(record.get("path") or "")
            if not raw_path:
                continue
            artifact_id = str(record.get("id") or f"{task_id}-artifact-{index}")
            self._insert_artifact_with_id(
                conn,
                task_id,
                artifact_id,
                str(record.get("kind") or "imported_artifact"),
                Path(raw_path),
                metadata=record.get("metadata") if isinstance(record.get("metadata"), dict) else {"name": Path(raw_path).name},
            )

    def _insert_imported_item(
        self,
        conn: sqlite3.Connection,
        table: str,
        id_column: str,
        task_id: str,
        item: Any,
        index: int,
        prefix: str,
    ) -> None:
        if not isinstance(item, dict):
            return
        item_id = str(item.get("id") or item.get("run_id") or f"imported-{prefix}-{index}")
        conn.execute(
            f"insert into {table}(task_id,{id_column},data) values(?,?,?)",
            (task_id, item_id, self._json(item)),
        )

    def _build_trace(
        self,
        task_id: str,
        finding: dict[str, Any],
        include_objects: bool,
    ) -> dict[str, Any]:
        candidate_id = str(finding.get("candidate_id") or "")
        slice_id = str(finding.get("slice_id") or "")
        dangerous_function_id = str(finding.get("dangerous_function_id") or "")
        tool_run_refs = [str(item) for item in finding.get("tool_run_refs") or [] if item]
        artifact_refs = [str(item) for item in finding.get("artifact_refs") or [] if item]
        with self.connect() as conn:
            candidate = self._read_item(conn, "candidates", "item_id", task_id, candidate_id)
            program_slice = self._read_item(conn, "program_slices", "item_id", task_id, slice_id)
            dangerous = self._read_item(conn, "dangerous_functions", "item_id", task_id, dangerous_function_id)
            if not dangerous_function_id and program_slice:
                dangerous_function_id = str(program_slice.get("dangerous_function_id") or "")
                dangerous = self._read_item(conn, "dangerous_functions", "item_id", task_id, dangerous_function_id)
            if not tool_run_refs and program_slice:
                tool_run_refs = [str(item) for item in program_slice.get("tool_run_refs") or [] if item]
            if not tool_run_refs and dangerous:
                tool_run_refs = [str(item) for item in dangerous.get("tool_run_refs") or [] if item]
            if not artifact_refs:
                for item in (candidate, program_slice, dangerous):
                    if isinstance(item, dict):
                        artifact_refs.extend(str(ref) for ref in item.get("artifact_refs") or [] if ref)
            tool_runs = self._read_tool_runs(conn, task_id, tool_run_refs)
            artifacts = self._read_artifacts(artifact_refs)
        if include_objects:
            return {
                "candidate_id": candidate_id,
                "slice_id": slice_id,
                "dangerous_function_id": dangerous_function_id,
                "tool_run_refs": tool_run_refs,
                "artifact_refs": artifact_refs,
                "candidate": candidate,
                "program_slice": program_slice,
                "dangerous_function": dangerous,
                "tool_runs": tool_runs,
                "artifacts": artifacts,
            }
        return {
            "candidate_id": candidate_id,
            "slice_id": slice_id,
            "dangerous_function_id": dangerous_function_id,
            "tool_run_refs": tool_run_refs,
            "artifact_refs": artifact_refs,
        }

    def _trace_summary(self, finding: dict[str, Any]) -> dict[str, Any]:
        return {
            "candidate_id": str(finding.get("candidate_id") or ""),
            "slice_id": str(finding.get("slice_id") or ""),
            "dangerous_function_id": str(finding.get("dangerous_function_id") or ""),
            "tool_run_refs": [str(item) for item in finding.get("tool_run_refs") or [] if item],
            "artifact_refs": [str(item) for item in finding.get("artifact_refs") or [] if item],
        }

    def _read_item(
        self,
        conn: sqlite3.Connection,
        table: str,
        id_column: str,
        task_id: str,
        item_id: str,
    ) -> dict[str, Any] | None:
        if not item_id:
            return None
        row = conn.execute(
            f"select data from {table} where task_id=? and {id_column}=?",
            (task_id, item_id),
        ).fetchone()
        return json.loads(row["data"]) if row else None

    def _read_tool_runs(
        self,
        conn: sqlite3.Connection,
        task_id: str,
        run_ids: list[str],
    ) -> list[dict[str, Any]]:
        if not run_ids:
            return []
        placeholders = ",".join("?" for _ in run_ids)
        rows = conn.execute(
            f"select data from tool_runs where task_id=? and run_id in ({placeholders})",
            [task_id, *run_ids],
        ).fetchall()
        return [json.loads(row["data"]) for row in rows]

    def _read_artifacts(self, artifact_ids: list[str]) -> list[dict[str, Any]]:
        if not artifact_ids:
            return []
        with self.connect() as conn:
            placeholders = ",".join("?" for _ in artifact_ids)
            rows = conn.execute(
                f"select * from artifacts where id in ({placeholders})",
                artifact_ids,
            ).fetchall()
        output: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["metadata"] = json.loads(item.get("metadata") or "{}")
            output.append(item)
        return output

    def _normalize_task(self, task: dict[str, Any]) -> dict[str, Any]:
        task["commit"] = task.get("commit_hash", "")
        task["llm_model"] = task.get("llm_model") or task.get("model", "")
        task["model"] = task.get("model") or task["llm_model"]
        task["llm_provider"] = task.get("llm_provider") or "deepseek"
        task["target_type"] = task.get("target_type") or self._infer_target_type(task.get("target", ""))
        task["current_agent"] = task.get("current_agent") or ""
        task["current_phase"] = task.get("current_phase") or ""
        task["progress_done"] = int(task.get("progress_done") or 0)
        task["progress_total"] = int(task.get("progress_total") or 0)
        task["enable_native_build"] = bool(task.get("enable_native_build", False))
        try:
            task["budget"] = AuditBudget.for_mode(task.get("mode") or "standard").to_dict()
        except ValueError:
            task["budget"] = AuditBudget.for_mode("standard").to_dict()
        return task

    def _file_metadata(self, path: Path) -> tuple[str, int]:
        if not path.exists() or not path.is_file():
            return "", 0
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest(), path.stat().st_size

    def _infer_target_type(self, target: str) -> str:
        value = target.strip().lower()
        if value.startswith(("http://", "https://", "git@", "ssh://")) or "/" in target and not Path(target).exists():
            return "github" if "github.com" in value or value.count("/") == 1 else "git"
        return "local"

    def _int_or_none(self, value: Any) -> int | None:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _json(self, value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, default=str)

    def _delete_task_files(self, report_dir: str, report_files: list[str], artifact_files: list[str]) -> None:
        for value in artifact_files:
            self._unlink_file(value)
        for value in report_files:
            self._unlink_file(value)
        if not report_dir:
            return
        path = Path(report_dir)
        if path.exists() and path.is_dir():
            shutil.rmtree(path, ignore_errors=True)

    def _unlink_file(self, value: str) -> None:
        if not value:
            return
        path = Path(value)
        if path.exists() and path.is_file():
            path.unlink(missing_ok=True)
