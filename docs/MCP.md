# MCP 接入说明

当前项目提供一个可选 MCP Server 入口：

```text
src/agentic_code_audit/mcp_server.py
```

安装 MCP 依赖：

```powershell
pip install -e ".[mcp]"
```

启动：

```powershell
python -m agentic_code_audit.mcp_server
```

暴露工具：

- `audit_local_path(target, output)`：审计本地源码目录，输出报告路径和漏洞数量。
- `profile_local_path(target)`：仅执行项目画像。

设计原则：

- MCP 只是工具调用入口，不直接保存密钥。
- DeepSeek API Key 仍然从环境变量或本地 `.env` 读取。
- `.env` 不提交到 GitHub。
- 外部扫描工具仍通过 CLI adapter 调用，后续可逐步替换为官方 MCP。
