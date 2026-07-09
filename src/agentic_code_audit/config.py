from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _load_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        values[key] = value
    return values


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    llm_provider: str
    llm_api_key: str
    llm_base_url: str
    llm_model: str
    max_files: int
    max_file_size: int
    tool_timeout: int
    auto_build_native: bool

    @property
    def deepseek_api_key(self) -> str:
        return self.llm_api_key

    @property
    def deepseek_base_url(self) -> str:
        return self.llm_base_url

    @property
    def deepseek_model(self) -> str:
        return self.llm_model

    @classmethod
    def load(cls, project_dir: Path | None = None) -> "Settings":
        file_values: dict[str, str] = {}
        if project_dir:
            file_values.update(_load_dotenv(project_dir / ".env"))
        file_values.update(_load_dotenv(Path.cwd() / ".env"))

        def value(name: str, default: str = "") -> str:
            return os.environ.get(name, file_values.get(name, default))

        def int_value(name: str, default: int) -> int:
            try:
                return int(value(name, str(default)))
            except ValueError:
                return default

        def bool_value(name: str, default: bool = False) -> bool:
            raw = value(name, str(default).lower())
            return raw.lower() in {"1", "true", "yes", "on"}

        llm_provider = value("LLM_PROVIDER", "deepseek")
        llm_api_key = value("LLM_API_KEY") or value("DEEPSEEK_API_KEY")
        llm_base_url = value("LLM_BASE_URL") or value("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
        llm_model = value("LLM_MODEL") or value("DEEPSEEK_MODEL", "deepseek-v4-pro")

        return cls(
            llm_provider=llm_provider,
            llm_api_key=llm_api_key,
            llm_base_url=llm_base_url,
            llm_model=llm_model,
            max_files=int_value("AUDIT_MAX_FILES", 5000),
            max_file_size=int_value("AUDIT_MAX_FILE_SIZE", 1_048_576),
            tool_timeout=int_value("AUDIT_TOOL_TIMEOUT", 120),
            auto_build_native=bool_value("AUDIT_AUTO_BUILD_NATIVE", False),
        )
