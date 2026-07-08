from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .models import AuditReport, utc_now


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
                """
            )

    def create_task(self, target: str, mode: str, model: str, runtime_url: str, enable_native_build: bool) -> str:
        task_id = str(uuid.uuid4())
        with self._lock, self.connect() as conn:
            conn.execute(
                """
                insert into tasks(id,target,mode,model,status,runtime_url,enable_native_build,created_at)
                values(?,?,?,?,?,?,?,?)
                """,
                (task_id, target, mode, model, "queued", runtime_url, int(enable_native_build), utc_now()),
            )
        self.add_event(task_id, "System", "task_created", f"任务已创建: {target}", {"target": target})
        return task_id

    def update_task(self, task_id: str, **fields: Any) -> None:
        if not fields:
            return
        columns = ", ".join(f"{key}=?" for key in fields)
        values = list(fields.values()) + [task_id]
        with self._lock, self.connect() as conn:
            conn.execute(f"update tasks set {columns} where id=?", values)

    def add_event(self, task_id: str, agent: str, event_type: str, message: str, metadata: dict[str, Any] | None = None) -> None:
        metadata = metadata or {}
        with self._lock, self.connect() as conn:
            row = conn.execute("select coalesce(max(sequence),0)+1 as seq from agent_events where task_id=?", (task_id,)).fetchone()
            sequence = int(row["seq"])
            conn.execute(
                """
                insert into agent_events(task_id,sequence,agent,event_type,message,metadata,created_at)
                values(?,?,?,?,?,?,?)
                """,
                (task_id, sequence, agent, event_type, message, json.dumps(metadata, ensure_ascii=False), utc_now()),
            )

    def get_task(self, task_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("select * from tasks where id=?", (task_id,)).fetchone()
        return dict(row) if row else None

    def list_tasks(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("select * from tasks order by created_at desc").fetchall()
        return [dict(row) for row in rows]

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
            for item in report.tool_results:
                conn.execute("insert into tool_runs values(?,?,?,?)", (task_id, item.tool, item.status, self._json(asdict(item))))
            for item in report.dangerous_functions:
                conn.execute("insert into dangerous_functions values(?,?,?)", (task_id, item.id, self._json(asdict(item))))
            for item in report.program_slices:
                conn.execute("insert into program_slices values(?,?,?)", (task_id, item.id, self._json(asdict(item))))
            for item in report.candidates:
                conn.execute("insert into candidates values(?,?,?)", (task_id, item.id, self._json(asdict(item))))
            for item in report.findings:
                conn.execute("insert into findings values(?,?,?)", (task_id, item.id, self._json(asdict(item))))
            for item in report.verification_results:
                conn.execute("insert into verification_attempts values(?,?,?)", (task_id, item.finding_id, self._json(asdict(item))))
            for kind, path in {"json_report": json_path, "markdown_report": markdown_path}.items():
                artifact_id = str(uuid.uuid4())
                conn.execute(
                    "insert into artifacts values(?,?,?,?,?)",
                    (artifact_id, task_id, kind, str(path), utc_now()),
                )
            conn.execute(
                "update tasks set json_report=?, markdown_report=?, report_dir=? where id=?",
                (str(json_path), str(markdown_path), str(json_path.parent), task_id),
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
            finding["verification"] = verifications.get(row["finding_id"])
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
        return data

    def get_artifact(self, artifact_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("select * from artifacts where id=?", (artifact_id,)).fetchone()
        return dict(row) if row else None

    def _json(self, value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, default=str)
