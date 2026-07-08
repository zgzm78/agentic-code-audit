# agentic-code-audit

DeepAudit 风格的多 Agent 源码安全审计平台，用 DeepSeek 驱动“危险函数定位 -> 切片分析 -> 候选漏洞生成 -> 线索汇聚 -> 漏洞类型判定 -> 沙箱验证 -> 报告”的完整链路。

当前版本采用轻量全栈架构：

```text
React/Vite frontend
  -> FastAPI backend + SSE
  -> OrchestratorAgent
  -> Recon / Tool / DangerousFunction / Slice / Candidate / Aggregator / Classifier / Verification / Report
  -> SQLite + artifacts
  -> Docker sandbox
```

## 当前功能

- 支持本地目录、Git URL、GitHub URL、`owner/repo` 输入。
- DeepSeek 必选，默认模型为 `deepseek-v4-pro`。
- 工具链支持 Semgrep、Bandit、Gitleaks、OSV-Scanner、npm audit 和内置危险函数规则。
- 漏洞挖掘按阶段输出危险函数、程序切片、候选漏洞、最终 finding。
- 验证阶段参考 DeepAudit 和 AnyPoC：由 LLM 设计 harness/PoC，在 Docker sandbox 中执行，并保存命令、退出码、stdout、stderr、脚本和生成文件。
- 前端提供任务创建、Agent 树、SSE 实时日志、finding 详情、链路图、验证证据和报告预览。
- `.env` 已加入 `.gitignore`，真实 API Key 不应提交到 GitHub。

## 快速开始

```powershell
cd C:\Users\fujs\Desktop\security-agent\agentic-code-audit
Copy-Item .env.example .env
notepad .env
```

`.env` 至少需要：

```env
DEEPSEEK_API_KEY=your-deepseek-api-key
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-v4-pro
```

### Docker 一键启动

```powershell
docker compose up --build
```

打开：

- Frontend: `http://127.0.0.1:3000`
- Backend health: `http://127.0.0.1:8000/api/health`

### 本地 CLI 运行

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
agentic-code-audit audit .\examples\vulnerable-python -o reports\demo
```

审计 GitHub 仓库：

```powershell
agentic-code-audit audit https://github.com/Exiv2/exiv2.git -o reports\exiv2
```

C/C++ 项目由系统自动判断是否需要 CMake + ASAN/UBSAN 构建：

```powershell
agentic-code-audit audit https://github.com/Exiv2/exiv2.git -o reports\exiv2
```

带运行目标 URL 做 HTTP 动态验证：

```powershell
agentic-code-audit audit .\examples\vulnerable-python -o reports\demo --runtime-url http://127.0.0.1:5000
```

## 安装本地安全工具

工具可以安装到仓库内 `.tools/`，不会污染系统 PATH：

```powershell
.\scripts\install_tools.ps1 -Proxy http://127.0.0.1:18081
```

安装后路径会被程序自动加入执行环境：

- Semgrep: `.tools\semgrep-venv\Scripts\semgrep.exe`
- Bandit: `.tools\semgrep-venv\Scripts\bandit.exe`
- Gitleaks: `.tools\bin\gitleaks.exe`
- OSV-Scanner: `.tools\bin\osv-scanner.exe`

## API

- `POST /api/tasks`: 创建审计任务。
- `GET /api/tasks`: 任务列表。
- `GET /api/tasks/{task_id}`: 任务详情。
- `GET /api/tasks/{task_id}/events`: SSE 实时事件流。
- `GET /api/tasks/{task_id}/findings`: finding 列表。
- `GET /api/tasks/{task_id}/findings/{finding_id}`: finding 详情、链路图、PoC、验证证据。
- `GET /api/tasks/{task_id}/report.md`: Markdown 报告。
- `GET /api/artifacts/{artifact_id}`: 下载 artifact。

## 输出

审计完成后会生成：

- `audit-report.json`
- `audit-report.md`
- `pocs/<finding-id>/bug_report.md`
- `pocs/<finding-id>/runbook.md`
- `pocs/<finding-id>/verification.json`
- sandbox 执行日志和 LLM 生成的 harness 脚本

## 测试

```powershell
python -m pytest tests
cd frontend
npm.cmd install
npm.cmd run build
```

## 文档

- [系统架构](docs/ARCHITECTURE.md)
- [DeepAudit 对比与重构说明](docs/DEEPAUDIT_COMPARISON.md)
- [使用说明](docs/USAGE.md)
- [Web 界面](docs/WEB.md)
- [MCP 接入](docs/MCP.md)

## 安全说明

本系统仅用于授权项目、课程实验和本地安全研究。PoC、harness 和动态验证必须在隔离环境中执行，不要对未授权目标运行利用代码。
