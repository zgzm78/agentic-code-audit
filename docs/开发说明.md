# 开发说明

## 目录结构

```text
agentic-code-audit/
  src/agentic_code_audit/
    agents/
      profiler.py
      analysis.py
      verification.py
    tools/
      builtin_patterns.py
      runner.py
    cli.py
    config.py
    llm.py
    models.py
    pipeline.py
    reporting.py
  docs/
  skills/
  examples/
  tests/
```

## 本地运行

```powershell
$env:PYTHONPATH="src"
python -m agentic_code_audit audit .\examples\vulnerable-python -o reports\demo
```

## 测试

```powershell
pip install -e ".[dev]"
pytest
```

## 增加新工具

在 `tools/runner.py` 中添加新方法：

```python
def run_trivy(self, target: Path) -> ToolResult:
    return self.command_runner.run_json_tool(
        "trivy",
        ["trivy", "fs", "--format", "json", str(target)],
        target,
    )
```

然后在 `SecurityToolRunner.run_all()` 中注册。

如果工具输出需要转成统一漏洞模型，在 `agents/analysis.py` 中添加解析函数。

## 密钥管理

不要把 API Key 写入源码、README、测试数据或提交记录。

只允许通过环境变量、本地 `.env` 或 CI/CD secret 读取密钥。
