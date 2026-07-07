from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    deepseek_api_key: str
    deepseek_base_url: str
    deepseek_model: str
    max_files: int
    max_file_size: int
    tool_timeout: int

    @classmethod
    def load(cls, project_dir: Path | None = None) -> "Settings":
        if project_dir:
            _load_dotenv(project_dir / ".env")
        _load_dotenv(Path.cwd() / ".env")

        return cls(
            deepseek_api_key=os.environ.get("DEEPSEEK_API_KEY", ""),
            deepseek_base_url=os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
            deepseek_model=os.environ.get("DEEPSEEK_MODEL", "deepseek-chat"),
            max_files=_int_env("AUDIT_MAX_FILES", 5000),
            max_file_size=_int_env("AUDIT_MAX_FILE_SIZE", 1_048_576),
            tool_timeout=_int_env("AUDIT_TOOL_TIMEOUT", 120),
        )
