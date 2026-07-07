# agentic-code-audit

基于大模型智能体的开源项目源码安全缺陷自动审计与验证系统。

本项目参考 DeepAudit 的 `Orchestrator + Recon + Analysis + Verification + Tools`
思路，并结合源码分析场景重新设计了审计流水线：

```text
项目输入 -> 项目画像 -> 源码语义建模 -> 工具扫描 -> LLM 语义审计
       -> 候选漏洞归并 -> 静态/动态验证 -> 报告与证据链输出
```

当前版本是一个可运行 MVP：

- 支持本地源码目录审计。
- 支持项目语言、框架、依赖文件、入口点和高风险文件识别。
- 内置规则覆盖 SQL 注入、命令注入、路径遍历、硬编码密钥。
- 自动尝试调用 Semgrep、Gitleaks、OSV-Scanner、Bandit、npm audit。
- 支持 DeepSeek API 增强分析，但没有 API Key 时也能离线运行。
- 输出 JSON 和 Markdown 审计报告。
- `.env` 已被 `.gitignore` 忽略，避免 API Key 泄露到 GitHub。

## 快速开始

```powershell
cd C:\Users\fujs\Desktop\security-agent\agentic-code-audit
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

配置 DeepSeek：

```powershell
Copy-Item .env.example .env
notepad .env
```

在 `.env` 中填写：

```env
DEEPSEEK_API_KEY=你的 DeepSeek API Key
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-chat
```

运行一次审计：

```powershell
agentic-code-audit audit .\examples\vulnerable-python -o reports\demo
```

离线运行，不调用 DeepSeek：

```powershell
agentic-code-audit audit .\examples\vulnerable-python -o reports\demo --no-llm
```

或者不安装包，直接用源码方式运行：

```powershell
$env:PYTHONPATH="src"
python -m agentic_code_audit audit .\examples\vulnerable-python -o reports\demo
```

输出文件：

- `reports/demo/audit-report.json`
- `reports/demo/audit-report.md`

## 文档

- [系统架构](docs/ARCHITECTURE.md)
- [使用说明](docs/USAGE.md)
- [开发说明](docs/DEVELOPMENT.md)
- [MCP 接入](docs/MCP.md)
- [路线图](docs/ROADMAP.md)
- [Agent Skill 模板](skills/source-code-audit/SKILL.md)

## 安全说明

本系统只应用于授权代码仓库和本地测试环境。动态验证和 PoC 执行必须在容器或隔离沙箱中进行。
