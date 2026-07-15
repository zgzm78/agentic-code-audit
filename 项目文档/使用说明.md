# 使用说明

## 1. 配置 DeepSeek

DeepSeek 是必选项。没有 `DEEPSEEK_API_KEY` 时，CLI 和 Web 任务都会拒绝启动审计流程。

```powershell
cd C:\Users\fujs\Desktop\security-agent\agentic-code-audit
Copy-Item .env.example .env
notepad .env
```

```env
DEEPSEEK_API_KEY=your-deepseek-api-key
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-v4-pro
```

`.env` 已加入 `.gitignore`，不要把真实 Key 提交到 GitHub。

## 2. Docker Compose 启动

```powershell
docker compose up --build
```

访问：

- 前端：`http://127.0.0.1:3000`
- 后端健康检查：`http://127.0.0.1:8000/api/health`

Compose 包含：

- `frontend`: React/Vite 审计界面。
- `backend`: FastAPI、SSE、SQLite、Agent 编排。
- `sandbox`: Python/Bash/JS/C/C++ 验证沙箱镜像。

## 3. CLI 安装与运行

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

本地项目：

```powershell
agentic-code-audit audit .\examples\vulnerable-python -o reports\demo
```

GitHub URL：

```powershell
agentic-code-audit audit https://github.com/Exiv2/exiv2.git -o reports\exiv2
```

`owner/repo`：

```powershell
agentic-code-audit audit Exiv2/exiv2 -o reports\exiv2-short
```

C/C++ 项目由系统自动判断是否需要构建：

```powershell
agentic-code-audit audit https://github.com/Exiv2/exiv2.git -o reports\exiv2
```

带运行目标 URL 做 HTTP 动态验证：

```powershell
agentic-code-audit audit .\examples\vulnerable-python -o reports\demo --runtime-url http://127.0.0.1:5000
```

## 4. 外部工具

系统会自动尝试调用：

- Semgrep
- Gitleaks
- OSV-Scanner
- Bandit
- npm audit
- 内置危险函数规则

安装到仓库本地 `.tools/`：

```powershell
.\scripts\install_tools.ps1 -Proxy http://127.0.0.1:18081
```

`.tools/` 已加入 `.gitignore`。

## 5. 审计流水线

一次任务会依次执行：

```text
Input/Recon
  -> Tool scan
  -> DangerousFunctionLocator
  -> SliceAnalyzer
  -> CandidateGenerator
  -> ClueAggregator
  -> VulnerabilityClassifier
  -> VerificationPlanner
  -> SandboxExecutor
  -> EvidenceChecker
  -> ReportWriter
```

每个关键阶段都会调用 DeepSeek 产出结构化判断或解释。

## 6. 报告与证据

输出目录包含：

- `audit-report.json`
- `audit-report.md`
- `pocs/<finding-id>/bug_report.md`
- `pocs/<finding-id>/runbook.md`
- `pocs/<finding-id>/verification.json`
- sandbox stdout/stderr、执行命令、harness 脚本

报告描述漏洞位置、触发条件、调用/数据流链路、PoC、验证证据和复现状态。
