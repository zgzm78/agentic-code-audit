from __future__ import annotations

from pathlib import Path

from .agents.recon import ReconAgent
from .config import Settings
from .inputs import TargetResolver
from .pipeline import AuditPipeline


try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:  # pragma: no cover
    raise SystemExit("Install MCP support with: pip install -e .[mcp]") from exc


mcp = FastMCP("agentic-code-audit")


@mcp.tool()
def audit_target(target: str, output: str = "reports/mcp", runtime_url: str = "") -> dict:
    """Audit a local path or Git/GitHub repository and return report paths plus finding count."""
    settings = Settings.load(Path.cwd())
    artifacts = AuditPipeline(settings).run(target, Path(output), runtime_url=runtime_url)
    return {
        "target": artifacts.report.target,
        "input_kind": artifacts.report.input_source.kind,
        "json_report": str(artifacts.json_path),
        "markdown_report": str(artifacts.markdown_path),
        "findings": len(artifacts.report.findings),
        "llm_enabled": artifacts.report.llm_enabled,
        "llm_provider": artifacts.report.llm_provider,
        "llm_model": artifacts.report.llm_model,
        "deepseek_enabled": artifacts.report.llm_enabled,
    }


@mcp.tool()
def profile_target(target: str) -> dict:
    """Profile a local path or Git/GitHub repository without running vulnerability analysis."""
    settings = Settings.load(Path.cwd())
    input_source = TargetResolver(Path.cwd() / "runs").resolve(target)
    profile, _ = ReconAgent(settings).run(Path(input_source.local_path))
    return profile.__dict__


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
