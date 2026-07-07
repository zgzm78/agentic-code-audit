# 使用说明

## 1. 安装

```powershell
cd C:\Users\fujs\Desktop\security-agent\agentic-code-audit
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

## 2. 配置 DeepSeek

```powershell
Copy-Item .env.example .env
notepad .env
```

填写：

```env
DEEPSEEK_API_KEY=你的 DeepSeek API Key
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-chat
```

注意：`.env` 已经在 `.gitignore` 中，不能提交到 GitHub。

## 3. 运行审计

```powershell
agentic-code-audit audit .\examples\vulnerable-python -o reports\demo
```

如果只想运行本地规则和外部 CLI 工具，不调用 DeepSeek：

```powershell
agentic-code-audit audit .\examples\vulnerable-python -o reports\demo --no-llm
```

参数：

- `target`：待审计源码目录。
- `-o/--output`：报告输出目录。
- `--project-dir`：读取 `.env` 的目录，默认当前目录。
- `--no-llm`：本次运行禁用 DeepSeek。

## 4. 外部工具

系统会自动尝试调用这些工具，未安装时会跳过：

- Semgrep
- Gitleaks
- OSV-Scanner
- Bandit
- npm audit

未安装外部工具也能运行，因为系统包含内置规则扫描器。

## 5. 报告

审计完成后生成：

```text
audit-report.json
audit-report.md
```

JSON 用于后续平台处理，Markdown 用于答辩、报告和人工复核。
