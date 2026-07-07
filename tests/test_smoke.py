from pathlib import Path
from dataclasses import replace

from agentic_code_audit.config import Settings
from agentic_code_audit.pipeline import AuditPipeline


def test_pipeline_smoke(tmp_path: Path):
    target = Path(__file__).resolve().parents[1] / "examples" / "vulnerable-python"
    settings = replace(Settings.load(), deepseek_api_key="")
    pipeline = AuditPipeline(settings)
    artifacts = pipeline.run(target, tmp_path)

    assert artifacts.json_path.exists()
    assert artifacts.markdown_path.exists()
    assert len(artifacts.report.findings) >= 2
