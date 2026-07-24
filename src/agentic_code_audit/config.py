from __future__ import annotations

import os
import json
from dataclasses import dataclass
from pathlib import Path


def _load_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
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


def _load_runtime_llm_settings(project_dir: Path) -> dict[str, str]:
    path = project_dir / "data" / "llm-settings.json"
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    return {
        str(key): str(value)
        for key, value in payload.items()
        if key in {"LLM_PROVIDER", "LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL"}
        and isinstance(value, str)
    }


def save_runtime_llm_settings(project_dir: Path, values: dict[str, str]) -> Path:
    data_dir = project_dir / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    path = data_dir / "llm-settings.json"
    current = _load_runtime_llm_settings(project_dir)
    current.update({key: value for key, value in values.items() if value is not None})
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(current, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path


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
    sandbox_container: str = "agentic-code-audit-sandbox"
    sandbox_image: str = "agentic-code-audit-sandbox:local"
    build_network_enabled: bool = False
    enable_codeql: bool = True
    codeql_timeout: int = 600
    codeql_pack_download: bool = True

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
        root = (project_dir or Path.cwd()).resolve()
        if project_dir:
            file_values.update(_load_dotenv(project_dir / ".env"))
        file_values.update(_load_dotenv(Path.cwd() / ".env"))
        runtime_values = _load_runtime_llm_settings(root)

        def value(name: str, default: str = "") -> str:
            return runtime_values.get(name, os.environ.get(name, file_values.get(name, default)))

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
            sandbox_container=value("AUDIT_SANDBOX_CONTAINER", "agentic-code-audit-sandbox"),
            sandbox_image=value("AUDIT_SANDBOX_IMAGE", "agentic-code-audit-sandbox:local"),
            build_network_enabled=bool_value("AUDIT_BUILD_NETWORK_ENABLED", False),
            enable_codeql=bool_value("AUDIT_ENABLE_CODEQL", True),
            codeql_timeout=int_value("AUDIT_CODEQL_TIMEOUT", 600),
            codeql_pack_download=bool_value("AUDIT_CODEQL_PACK_DOWNLOAD", True),
        )
