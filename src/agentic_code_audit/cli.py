from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import Settings
from .pipeline import AuditPipeline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentic-code-audit",
        description="Agentic source code security audit and verification system.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    audit = subparsers.add_parser("audit", help="Audit a local directory or Git/GitHub repository.")
    audit.add_argument("target", help="Local project directory, GitHub URL, Git URL, or owner/repo.")
    audit.add_argument(
        "-o",
        "--output",
        default="reports/latest",
        help="Output directory for JSON and Markdown reports.",
    )
    audit.add_argument(
        "--project-dir",
        default=".",
        help="Directory used to load .env. Defaults to current working directory.",
    )
    audit.add_argument(
        "--runtime-url",
        default="",
        help="Optional running target base URL for HTTP dynamic probes, e.g. http://127.0.0.1:5000.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "audit":
        settings = Settings.load(Path(args.project_dir))
        if not settings.llm_api_key:
            print("LLM API key is required. Configure LLM_API_KEY or DEEPSEEK_API_KEY.", file=sys.stderr)
            return 2
        pipeline = AuditPipeline(settings)
        try:
            artifacts = pipeline.run(args.target, Path(args.output), runtime_url=args.runtime_url)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        print(f"JSON report: {artifacts.json_path}")
        print(f"Markdown report: {artifacts.markdown_path}")
        print(f"Findings: {len(artifacts.report.findings)}")
        print(f"LLM enabled: {artifacts.report.llm_enabled}")
        print(f"LLM provider: {artifacts.report.llm_provider}")
        print(f"LLM model: {artifacts.report.llm_model}")
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
