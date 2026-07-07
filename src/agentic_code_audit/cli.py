from __future__ import annotations

import argparse
import sys
from dataclasses import replace
from pathlib import Path

from .config import Settings
from .pipeline import AuditPipeline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentic-code-audit",
        description="Agentic source code security audit and verification system.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    audit = subparsers.add_parser("audit", help="Audit a local source code directory.")
    audit.add_argument("target", help="Local project directory to audit.")
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
        "--no-llm",
        action="store_true",
        help="Disable DeepSeek analysis for this run even when DEEPSEEK_API_KEY is configured.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "audit":
        target = Path(args.target)
        if not target.exists() or not target.is_dir():
            print(f"Target directory does not exist: {target}", file=sys.stderr)
            return 2

        settings = Settings.load(Path(args.project_dir))
        if args.no_llm:
            settings = replace(settings, deepseek_api_key="")
        pipeline = AuditPipeline(settings)
        artifacts = pipeline.run(target, Path(args.output))
        print(f"JSON report: {artifacts.json_path}")
        print(f"Markdown report: {artifacts.markdown_path}")
        print(f"Findings: {len(artifacts.report.findings)}")
        print(f"DeepSeek enabled: {artifacts.report.llm_enabled}")
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
