# Web 界面

当前 Web 界面是 React/Vite + FastAPI，不再使用旧的标准库 `http.server` 页面。

## 启动

```powershell
docker compose up --build
```

打开：

```text
http://127.0.0.1:3000
```

后端：

```text
http://127.0.0.1:8000/api/health
```

## 页面能力

- 创建审计任务，输入本地路径、GitHub URL、Git URL 或 `owner/repo`。
- DeepSeek 配置检查：没有 API Key 时后端拒绝创建任务。
- SSE 实时日志：展示 Agent thought、tool_start、tool_end、finding、verification、report 等事件。
- Agent 树：Input、Recon、Tool、DangerousFunction、Slice、Candidate、Aggregator、Classifier、Verification、Report。
- Finding 列表：漏洞类型、严重性、置信度、验证状态。
- Finding 详情：解释、代码片段、触发条件、PoC、sandbox stdout/stderr。
- 链路图：展示 source、function、condition、sink、effect、artifact 的触发链。
- 报告预览和 Markdown 下载。

## API

- `POST /api/tasks`
- `GET /api/tasks`
- `GET /api/tasks/{task_id}`
- `GET /api/tasks/{task_id}/events`
- `GET /api/tasks/{task_id}/findings`
- `GET /api/tasks/{task_id}/findings/{finding_id}`
- `GET /api/tasks/{task_id}/report.md`
- `GET /api/artifacts/{artifact_id}`
