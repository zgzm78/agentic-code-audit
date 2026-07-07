from __future__ import annotations

from pathlib import Path

from .config import Settings
from .pipeline import AuditPipeline


try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:  # pragma: no cover
    raise SystemExit("Install MCP support with: pip install -e .[mcp]") from exc


mcp = FastMCP("agentic-code-audit")


@mcp.tool()
def audit_local_path(target: str, output: str = "reports/mcp") -> dict:
    """Audit a local source-code directory and return report paths plus finding count."""
    target_path = Path(target).resolve()
    if not target_path.exists() or not target_path.is_dir():
        raise ValueError(f"Target directory does not exist: {target_path}")

    settings = Settings.load(Path.cwd())
    artifacts = AuditPipeline(settings).run(target_path, Path(output))
    return {
        "target": str(target_path),
        "json_report": str(artifacts.json_path),
        "markdown_report": str(artifacts.markdown_path),
        "findings": len(artifacts.report.findings),
        "deepseek_enabled": artifacts.report.llm_enabled,
    }


@mcp.tool()
def profile_local_path(target: str) -> dict:
    """Profile a local source-code directory without running vulnerability analysis."""
    target_path = Path(target).resolve()
    if not target_path.exists() or not target_path.is_dir():
        raise ValueError(f"Target directory does not exist: {target_path}")

    settings = Settings.load(Path.cwd())
    profile = AuditPipeline(settings).profiler.profile(target_path)
    return profile.__dict__


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
