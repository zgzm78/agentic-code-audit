from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class RulesLoader:
    def __init__(self, root: Path | None = None) -> None:
        self.root = (root or Path.cwd() / "rules").resolve()

    def load(self) -> dict[str, Any]:
        files = {
            "common.cwe_mapping": self.root / "common" / "cwe_mapping.yml",
            "python.dangerous_apis": self.root / "python" / "dangerous_apis.yml",
            "javascript.dangerous_apis": self.root / "javascript" / "dangerous_apis.yml",
            "cpp.dangerous_functions": self.root / "cpp" / "dangerous_functions.yml",
            "cpp.sources": self.root / "cpp" / "sources.yml",
            "cpp.sanitizers": self.root / "cpp" / "sanitizers.yml",
        }
        loaded: dict[str, Any] = {}
        for key, path in files.items():
            loaded[key] = self._read_json_yaml(path)
        return loaded

    def _read_json_yaml(self, path: Path) -> Any:
        if not path.exists():
            return {}
        text = path.read_text(encoding="utf-8")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {}
