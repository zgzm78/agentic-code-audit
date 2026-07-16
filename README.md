# agentic-code-audit

agentic-code-audit 是一个基于大模型智能体的开源项目安全审计与漏洞验证系统，面向 GitHub/GitLab 仓库或本地代码目录，自动完成项目识别、工具探测、漏洞挖掘、漏洞验证和报告生成。系统将漏洞挖掘与验证拆分为多个协作 Agent，并结合 SAST 工具、Docker 沙箱、构建/运行证据和结构化报告，尽量把“发现了什么、为什么可疑、验证到了哪一步、证据是什么”完整保留下来，便于后续复现、分析和人工确认。

## 系统组成

```text
React/Vite frontend
  -> FastAPI backend + SSE events
  -> OrchestratorAgent
  -> Recon / Semantic / MiningDirector / Mining / Verification / Report
  -> SQLite + reports + artifacts
  -> Docker sandbox
```

- `frontend`: Web 界面，负责新建调查、实时日志、finding 列表、证据链、验证详情和报告预览。
- `backend`: FastAPI 服务，负责任务管理、Agent 编排、报告导入、API 与 SSE 事件流。
- `sandbox`: 无网络 Docker 容器，提供 C/C++、Python、Java、Go、PHP、Node 等验证和分析所需的基础运行环境。
- `reports/`: 保存 `audit-report.json`、`audit-report.md`、PoC、验证日志和导入的历史报告。
- `data/agentic-code-audit.sqlite3`: 保存任务、事件、finding、验证结果和报告索引。

## 当前能力

- 支持本地目录、Git URL、GitHub URL、GitLab URL 和 `owner/repo` 输入。
- 支持 `quick`、`standard`、`deep` 三种审计模式；模式主要影响预算、候选数量和 LLM 复核深度。
- 默认使用 DeepSeek，也支持通过 `LLM_BASE_URL` 接入 OpenAI-compatible API。
- 挖掘阶段会识别项目语言、构建文件、入口点、高风险文件、危险函数、程序切片、候选漏洞和最终 finding。
- MiningDirector 会让 LLM 生成挖掘策略，包括关注目录、优先函数、工具选择、harness 建议和 oracle 建议；系统会对策略做路径和安全校验。
- 验证阶段先做静态复核，再按条件进入动态验证；动态验证由 LLM 生成结构化验证方案，系统在安全策略内执行 CLI、harness 或局部 proof。
- C/C++ native build 默认关闭，需要任务级 `enable_native_build` 或环境策略显式开启；构建默认离线，`AUDIT_BUILD_NETWORK_ENABLED=false`。
- Docker 缺失、sandbox 不可用、构建失败、二进制缺失等情况会记录为明确的 blocked reason，不会伪造 `verified` 结论。
- 前端会展示静态验证、动态验证、checker、构建状态、局部 proof 等标签，旧报告也会尽量从已有字段推导展示。
- `reports/*/audit-report.json` 可以被后端导入历史记录，用于在前端查看外部复制过来的报告。

## 快速开始

```powershell
cd C:\Users\fujs\Desktop\security-agent\agentic-code-audit
Copy-Item .env.example .env
notepad .env
```

`.env` 至少需要配置：

```env
LLM_PROVIDER=deepseek
LLM_API_KEY=your-llm-api-key
LLM_BASE_URL=https://api.deepseek.com
LLM_MODEL=deepseek-v4-pro
```

兼容旧配置：

```env
DEEPSEEK_API_KEY=
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-v4-pro
```

## Docker 运行

启动并重建全部服务：

```powershell
docker compose up -d --build
```

查看状态：

```powershell
docker compose ps
```

停止系统：

```powershell
docker compose down
```

访问地址：

- Frontend: `http://127.0.0.1:3000`
- Backend health: `http://127.0.0.1:8000/api/health`
- Tool status: `http://127.0.0.1:8000/api/tools`

Compose 会启动三个服务：`backend`、`frontend` 和长期运行的无网络 `sandbox`。验证阶段仍可能按任务创建临时构建/验证容器，但验证执行始终不允许联网。

## 本地 CLI

CLI 适合快速跑一次本地或 Git 目标审计：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
agentic-code-audit audit .\examples\vulnerable-python -o reports\demo
```

审计远程仓库：

```powershell
agentic-code-audit audit https://github.com/Exiv2/exiv2.git -o reports\exiv2
```

对已经运行的 Web 服务目标做 HTTP 动态验证：

```powershell
agentic-code-audit audit .\examples\vulnerable-python -o reports\demo --runtime-url http://127.0.0.1:5000
```

更多模式选择、任务启动/取消、native build 开关和历史报告导入建议使用 Web 界面或 API。

## 工具与沙箱

后端和 sandbox 会共同提供工具能力。`/api/tools` 会标明工具运行位置、容器和网络策略，避免把 backend PATH 误判成 sandbox 能力。

常见工具包括：

- backend/通用工具：`semgrep`、`bandit`、`gitleaks`、`osv-scanner`、`npm audit`、`trivy` 等。
- sandbox/验证工具：`cppcheck`、`clang-tidy`、`ctags`、`cmake`、`make`、`gcc/g++`、`clang/clang++`、`python/pytest`、`node/npm`、`go`、`java/maven/gradle`、`php/composer` 等。

可选安装本地工具到仓库内 `.tools/`：

```powershell
.\scripts\install_tools.ps1 -Proxy http://127.0.0.1:18081
```

## API

- `GET /api/health`: 服务健康状态。
- `GET /api/tools`: 工具可用性、运行位置和网络策略。
- `GET /api/settings/llm`: 读取 LLM 配置。
- `PUT /api/settings/llm`: 更新 LLM 配置。
- `POST /api/settings/llm/test`: 测试 LLM 配置。
- `POST /api/tasks`: 创建审计任务。
- `POST /api/tasks/{task_id}/start`: 启动审计任务。
- `POST /api/tasks/{task_id}/cancel`: 取消任务。
- `GET /api/tasks`: 任务列表；会同步导入 `reports/*/audit-report.json`。
- `GET /api/tasks/{task_id}`: 任务详情。
- `GET /api/tasks/{task_id}/events`: SSE 实时事件流。
- `GET /api/tasks/{task_id}/events/history`: 历史事件。
- `GET /api/tasks/{task_id}/findings`: finding 列表。
- `GET /api/tasks/{task_id}/findings/{finding_id}`: finding 详情、链路图、PoC、验证证据。
- `GET /api/tasks/{task_id}/profile`: 项目画像。
- `GET /api/tasks/{task_id}/report.md`: Markdown 报告。
- `GET /api/tasks/{task_id}/report.json`: JSON 报告。
- `GET /api/tasks/{task_id}/mining-debug.json`: 挖掘调试信息。
- `GET /api/artifacts/{artifact_id}`: 下载 artifact。

## 输出文件

一次审计完成后，报告目录通常包含：

- `audit-report.json`: 前端和 API 使用的结构化报告。
- `audit-report.md`: 面向人工阅读的 Markdown 报告。
- `mining-debug.json`: 危险函数、切片、候选、聚合和 finding 计数等挖掘调试信息。
- `pocs/<finding-id>/`: 单个 finding 的 PoC、runbook、验证日志、harness 源码和执行记录。
- 构建日志、sandbox 命令、stdout、stderr、exit code、checker 明细和 fallback attempt。

## 测试

后端测试：

```powershell
python -m pytest
```

前端生产构建：

```powershell
cd frontend
npm.cmd install
npm.cmd run build
```

Compose 配置检查：

```powershell
docker compose config
```

## 安全说明

本系统仅用于授权项目、课程实验和本地安全研究。不要对未授权目标运行 PoC、harness 或动态验证。构建默认离线，验证始终无网络；LLM 输出只用于策略和验证方案建议，不能绕过用户授权、网络策略、sandbox 策略或证据结论。
